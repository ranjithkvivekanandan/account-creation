from botocore.exceptions import ClientError
import boto3
import os
import logging
import json
import time
import uuid

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

region = os.environ['AWS_DEFAULT_REGION']

cloudformation_client = boto3.client('cloudformation')

sts_client = boto3.client('sts')


headers = {
    'Content-Type': 'application/json'
}


def lambda_handler(event, context):
    logger.debug("Received event: %s for provisioning account onboarding", json.dumps(event))

    request = json.loads(event['body'])

    new_aws_account = request['accountId']

    onboarding_region = request['region']


    log_pipeline_provisioning_template_location = get_mandatory_evar("LOG_DESTINATION_CFT_LOCATION")


    logging_account_trust_role = get_mandatory_evar("LOGGING_ACCOUNT_TRUST_ROLE")

    response = sts_client.assume_role(
        RoleArn=logging_account_trust_role,
        DurationSeconds=1800,
        RoleSessionName="devops-account-sessison-"+str(uuid.uuid4())
    )


    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    cft_client = session.client('cloudformation',onboarding_region)

    stack_name = "pac-{}-log-pipeline-provisioning".format(new_aws_account)


    log_destination_provisoned = False


    try:
        describe_stack_response = cft_client.describe_stacks(StackName=stack_name)
        logger.info("describe_stack_response is {}".format(str(describe_stack_response)))
        stack = describe_stack_response['Stacks'][0]
        if stack['StackStatus'] in ['CREATE_COMPLETE','UPDATE_COMPLETE']:
            log_destination_provisoned = True
        else:
            return {
                'statusCode': 500,
                'headers': headers,
                'body': json.dumps({"message": "Log Desitantion is in {} state for the region. please fix or wait before doing retry!".format(stack['StackStatus'])})
            }
    except Exception as e:
        logger.error(str(e))

    if not log_destination_provisoned:
        create_stack_response = cft_client.create_stack(
                        StackName= stack_name,
                        TemplateURL=log_pipeline_provisioning_template_location,
                        Parameters=[
                            {
                                'ParameterKey': 'AccountId',
                                'ParameterValue': new_aws_account
                            }],
                        Capabilities=['CAPABILITY_NAMED_IAM'],
                        EnableTerminationProtection=True)

        logger.info("Create stack response is {} ".format(create_stack_response))


        time.sleep(5)

        stack_status =cft_client.describe_stacks(StackName= stack_name)

        logger.info("log bucket provisioning status is {} ".format(str(stack_status)))

        if len(stack_status['Stacks'])==0:
            raise Exception("Unable to find the log bucket stack")


        status = stack_status['Stacks'][0]['StackStatus']

        if 'Outputs' in stack_status['Stacks'][0]:
            outputs = stack_status['Stacks'][0]['Outputs']


        while status == 'CREATE_IN_PROGRESS':
            time.sleep(20)
            stack_status = cft_client.describe_stacks(StackName=stack_name)
            status = stack_status['Stacks'][0]['StackStatus']
            logger.info("log destination provisioning status is {} ".format(str(stack_status)))

        if status == 'CREATE_COMPLETE':
            log_destination_provisoned = True
        else:
            return {
                'statusCode': 500,
                'headers': headers,
                'body': json.dumps(
                    {"message": "Log Desitantion is in failed state for teh region. please fix before doing retry!"})
            }



    region_onboarding_stackset = get_mandatory_evar("REGION_ONBOARDING_STACKSET")


    try:
        response = cloudformation_client.create_stack_instances(
            StackSetName=region_onboarding_stackset,
            Accounts=[
                new_aws_account
            ],
            Regions=[onboarding_region
                     ]
        )

        logger.info("Stack instance response for region onboarding {}  ".format(str(response)))

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({"message":"Region Onbaording Request Successfully received."})
        }

    except Exception as e:
        logger.info("Region Onbaording has some issues. Please check")

        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message":"Region Onbaording Request failed with error {} ".format(str(e))})
        }


def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]

