from botocore.exceptions import ClientError
import boto3
import os
import logging
import json
import time
import uuid
from boto3.dynamodb.conditions import Key, Attr


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

region = os.environ['AWS_DEFAULT_REGION']

cloudformation_client = boto3.client('cloudformation')

def parse_params(event):
    params_list = []
    features = event.get("features")
    if features is None or features.get('account_onboarding') is None:
        return params_list
    features = features.get('account_onboarding')
    logger.info("parse params called with {} ".format(str(event)))
    
    for param in features:
        val = features.get(param, '')
        if val in [True, False, 'true', 'false']:
            val = 'Required' if val else 'NotRequired'
        params_list.append({"ParameterKey": param, "ParameterValue": val } )

    logger.info("generated params {}".format(str(params_list)))
    
    return params_list

def dynamodb_features_entry(event):
    try: 
        # Adding features list in accounts dynamodb table
        dynamodb = boto3.resource('dynamodb')
        table = get_mandatory_evar("ACCOUNTS_TABLE")
        accounts_table = dynamodb.Table(get_mandatory_evar("ACCOUNTS_TABLE"))

        new_item = json.dumps(event['features'])
        logger.info("New Items : {} ".format(new_item))

        response = accounts_table.scan(
            FilterExpression=Key('accountId').eq(event['accountId'])
        )
        logger.info("DynamoDB Scan table response {} ".format(str(response)))
        
        item = response['Items']
        #print("item: " + str(item[0]))
        request_id = item[0]['requestId']

        dynamodb_client = boto3.client('dynamodb')
        response = dynamodb_client.update_item(
            TableName=table,
            Key={
                'requestId':{"S": request_id}
            },
            UpdateExpression="SET features = :element",
            ExpressionAttributeValues={
                ":element": {"S": new_item}
            }
        )  
        logger.info(response)
    except Exception as e:
        logger.info(str(e))
        print(str(e))


def lambda_handler(event, context):
    logger.debug("Received event: %s for provisioning account onboarding", json.dumps(event))

    result = event
    if 'action' not in event:
        if event['accountCreationStatus'] != 'COMPLETED' or event['provisioningLogBucketStatus'] != 'COMPLETED':
            logger.info("provsioningLogBucketStatus or accountCreationStatus is incomplete . Hence skipping this step")
            result['accountOnboardingStatus'] = 'SKIPPED'
            return result

    new_aws_account = event['accountId']

    params = parse_params(event)
    
    account_onboarding_stackset = get_mandatory_evar("ACCOUNT_ONBOARDING_STACKSET")
    delete_vpc_function = get_mandatory_evar("DELETE_VPC_FUNCTION")
    account_onboarding_region = get_mandatory_evar("ACCOUNT_ONBOARDING_REGION")

    try:
        response = cloudformation_client.list_stack_instances(
            StackSetName=account_onboarding_stackset,
            StackInstanceAccount=new_aws_account,
            StackInstanceRegion=account_onboarding_region
        )
      
        account_exist = [ x['Account'] for x in response['Summaries'] if x['Account'] == event['accountId'] ] 
        
        if account_exist:
            if len(params) > 0:
                response = cloudformation_client.update_stack_instances(
                    StackSetName=account_onboarding_stackset,
                    Accounts=[new_aws_account],
                    Regions=[account_onboarding_region],
                    ParameterOverrides=params,
                    OperationPreferences={
                        'MaxConcurrentPercentage': 50,
                        'FailureTolerancePercentage': 100
                    })
            else:
                response = cloudformation_client.update_stack_instances(
                    StackSetName=account_onboarding_stackset,
                    Accounts=[new_aws_account],
                    Regions=[account_onboarding_region],
                    OperationPreferences={
                        'MaxConcurrentPercentage': 50,
                        'FailureTolerancePercentage': 100
                    })

        else:    
            if len(params) > 0:
                response = cloudformation_client.create_stack_instances(
                    StackSetName=account_onboarding_stackset,
                    Accounts=[new_aws_account],
                    Regions=[account_onboarding_region],
                    ParameterOverrides=params,
                    OperationPreferences={
                        'MaxConcurrentPercentage': 100,
                        'FailureTolerancePercentage': 100
                    })
            else:
                response = cloudformation_client.create_stack_instances(
                    StackSetName=account_onboarding_stackset,
                    Accounts=[new_aws_account],
                    Regions=[account_onboarding_region],
                    OperationPreferences={
                        'MaxConcurrentPercentage': 100,
                        'FailureTolerancePercentage': 100
                    })


        logger.info("Stack instance response for new account {} ".format(str(response)))

        operation_id = response['OperationId']

        status_response = cloudformation_client.describe_stack_set_operation(
            StackSetName=account_onboarding_stackset,
            OperationId=operation_id
        )

        count = 0
        status = "RUNNING"
        while status_response['StackSetOperation']['Status']=='RUNNING':
            # Terminate the wait condition after 4 mins
            count += 1
            if count > 8:
                break
            time.sleep(30)
            status_response = cloudformation_client.describe_stack_set_operation(
                StackSetName=account_onboarding_stackset,
                OperationId=operation_id
            )
            status = status_response['StackSetOperation']['Status']
            
        result['accountOnboardingStatus'] = status
        
        if status =='SUCCEEDED':
            result['accountOnboardingStatus'] = 'COMPLETED'
            if 'action' in event and event['action'] == 'update' and len(params) > 0:
                dynamodb_features_entry(event)
                
        if 'action' not in event:
            lambda_client = boto3.client('lambda')
            invoke_response = lambda_client.invoke(FunctionName=delete_vpc_function,
                                           InvocationType='RequestResponse',
                                           Payload=new_aws_account
                                           )
            delete_vpc_result = json.loads(invoke_response['Payload'].read())
            logger.info("VPC Deletion result {}".format(delete_vpc_result))
    
            result['defaultVPCDeletionStatus'] = delete_vpc_result['status']
            
    except Exception as e:
        logger.info("Creation of Account Onboarding has some issues. Please check")
        result['accountOnboardingStatus'] = 'FAILED'
        print(str(e))

    return result


def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]
