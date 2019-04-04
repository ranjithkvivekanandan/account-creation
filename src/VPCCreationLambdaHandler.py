from botocore.exceptions import ClientError
import boto3
import os
import json
from custom_resource_handler import VPCCalculator, ExpungeDefaultVPC
from lib.crhelper import cfn_handler
from lib.logger import Logger
import logging
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


region = os.environ['AWS_DEFAULT_REGION']

cloudformation_client = boto3.client('cloudformation')

headers = {
    'Content-Type': 'application/json'
}


def create_vpc(event):

    vpc_types = {
      "1-Tier-2-AZ-Public-VPC": {
        "AvailabilityZones": 2,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR"
        ],
        "PrivateSubnets": [
          
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "false",
        "CreatePublicSubnets": "true"
      },
      "1-Tier-3-AZ-Public-VPC": {
        "AvailabilityZones": 3,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR",
          "PublicSubnet3CIDR"
        ],
        "PrivateSubnets": [
          
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "false",
        "CreatePublicSubnets": "true"
      },
      "1-Tier-4-AZ-Public-VPC": {
        "AvailabilityZones": 4,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR",
          "PublicSubnet3CIDR",
          "PublicSubnet4CIDR"
        ],
        "PrivateSubnets": [
          
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "false",
        "CreatePublicSubnets": "true"
      },
      "1-Tier-2-AZ-Private-VPC": {
        "AvailabilityZones": 2,
        "PublicSubnets": [
          
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR"
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "false"
      },
      "1-Tier-3-AZ-Private-VPC": {
        "AvailabilityZones": 3,
        "PublicSubnets": [
          
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR",
          "PrivateSubnet3ACIDR"
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "false"
      },
      "1-Tier-4-AZ-Private-VPC": {
        "AvailabilityZones": 4,
        "PublicSubnets": [
          
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR",
          "PrivateSubnet3ACIDR",
          "PrivateSubnet4ACIDR"
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "false"
      },
      "2-Tier-2-AZ-Public-Private-VPC": {
        "AvailabilityZones": 2,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR"
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR"
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "true"
      },
      "2-Tier-3-AZ-Public-Private-VPC": {
        "AvailabilityZones": 3,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR",
          "PublicSubnet3CIDR"
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR",
          "PrivateSubnet3ACIDR"
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "true"
      },
      "2-Tier-4-AZ-Public-Private-VPC": {
        "AvailabilityZones": 4,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR",
          "PublicSubnet3CIDR",
          "PublicSubnet4CIDR"
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR",
          "PrivateSubnet3ACIDR",
          "PrivateSubnet4ACIDR"
        ],
        "CreateAdditionalPrivateSubnets": "false",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "true"
      },
      "3-Tier-2-AZ-Public-Private-Private-VPC": {
        "AvailabilityZones": 2,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR"
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR",
          "PrivateSubnet1BCIDR",
          "PrivateSubnet2BCIDR"
        ],
        "CreateAdditionalPrivateSubnets": "true",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "true"
      },
      "3-Tier-3-AZ-Public-Private-Private-VPC": {
        "AvailabilityZones": 3,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR",
          "PublicSubnet3CIDR"
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR",
          "PrivateSubnet3ACIDR",
          "PrivateSubnet1BCIDR",
          "PrivateSubnet2BCIDR",
          "PrivateSubnet3BCIDR"
        ],
        "CreateAdditionalPrivateSubnets": "true",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "true"
      },
      "3-Tier-4-AZ-Public-Private-Private-VPC": {
        "AvailabilityZones": 4,
        "PublicSubnets": [
          "PublicSubnet1CIDR",
          "PublicSubnet2CIDR",
          "PublicSubnet3CIDR",
          "PublicSubnet4CIDR"
        ],
        "PrivateSubnets": [
          "PrivateSubnet1ACIDR",
          "PrivateSubnet2ACIDR",
          "PrivateSubnet3ACIDR",
          "PrivateSubnet4ACIDR",
          "PrivateSubnet1BCIDR",
          "PrivateSubnet2BCIDR",
          "PrivateSubnet3BCIDR",
          "PrivateSubnet4BCIDR"
        ],
        "CreateAdditionalPrivateSubnets": "true",
        "CreatePrivateSubnets": "true",
        "CreatePublicSubnets": "true"
      }
    }
    
    logger.debug("Received event: %s for provisioning account onboarding", json.dumps(event))
    # event = json.loads(event['body'])

    if 'accountId' not in event or 'region' not in event or 'vpcProperties' not in event:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message": "VPC Onbaording failed because bad input payload. accountId,region,vpcProperties Mandatory. "})
        }

    if 'Type' not in event['vpcProperties'] or 'VPCCidr' not in event['vpcProperties'] or event['vpcProperties']['Type'] not in vpc_types:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message": "VPC Onboarding failed because bad vpcProperties. Type,VPCCidr must be valid "})
        }
    
    if 'action' not in event:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message": "VPC Onbaording failed because bad input payload.  parameter action is mandatory. "})
        }

    vpc_input = {}
    vpc_input['ResourceProperties'] = vpc_types.get(event['vpcProperties']['Type'])
    vpc_input['ResourceProperties']['VPCCidr'] = event['vpcProperties']['VPCCidr']
    vpc_input['ResourceProperties']['Region'] = event['region']

    logger.info("VPC ResourceProperties: {} ".format(str(vpc_input)))

    vpc = VPCCalculator(vpc_input, logger)
    logger.info("Running VPC Calculator - CR Router")
    vpc_params = vpc.calculate_vpc_parameters()
    logger.info("Response from Calculate VPC Parameters Handler")
    logger.info(vpc_params)
    # print(vpc_params)
    aws_account = event['accountId']

    onboarding_region = event['region']

    region_onboarding_stackset = get_mandatory_evar("REGION_ONBOARDING_STACKSET")

    try:
        response = cloudformation_client.list_stack_instances(
            StackSetName=region_onboarding_stackset,
            StackInstanceAccount=aws_account,
            StackInstanceRegion=onboarding_region
        )
        print(response)
        
        if len(response['Summaries']) <= 0:
            
            return {
                'statusCode': 500,
                'headers': headers,
                'body': json.dumps({"message":"Region Onbaording stack not deployed in the specified region"})
            }
        else:
          
            region_exist = [ x['Region'] for x in response['Summaries'] if x['Status'] == 'CURRENT' and x['Region'] == onboarding_region ] 
            if region_exist == None:
                return {
                    'statusCode': 500,
                    'headers': headers,
                    'body': json.dumps({"message":"Region Onbaording stack not deployed in the specified region"})
                }
        
    except Exception as e:
        logger.info("Describe stack instance. Please check")
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message":"Region Onbaording stack not deployed in the specified region {} ".format(str(e))})
        }    
        
    vpc_stackset = get_mandatory_evar("VPC_STACKSET")

    params = flatten_params_dict(vpc_params['Parameters'])

    try:
        response = cloudformation_client.create_stack_instances(
            StackSetName=vpc_stackset,
            Accounts=[
                aws_account
            ],
            Regions=[onboarding_region
                      ],
            ParameterOverrides= params)

        logger.info("Stack instance response for region onboarding {}  ".format(str(response)))

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({"message":"VPC Creation Request Successfully received."})
        }

    except Exception as e:
        logger.info("Creation of log bucket has some issues. Please check")

        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message":"VPC Creation Request failed with error {} ".format(str(e))})
        }

def delete_default_vpc(event):
    try:
        logger.info(event)
        ec2 = ExpungeDefaultVPC(event, logger)
        logger.info("Deleting VPCs and dependencies - CR Router")
        response = ec2.expunge_default_vpc()
        logger.info("Response from ExpungeVPC CR Handler")
        logger.info(response)
        return {
              'statusCode': 200,
              'headers': headers,
              'body': json.dumps({"message":"default VPC Successfully deleted."})
           }
    except Exception as e:
        message = {'EXCEPTION': str(e)}
        logger.exception(message)

def lambda_handler(event, context):
    logger.debug("Received event: %s for provisioning account onboarding", json.dumps(event))
    try:    
       
        if event['action'] == 'create':
            return create_vpc(event)
        elif event['action'] == 'delete_default':
            return delete_default_vpc(event)
            
  
    except Exception as e:
        logger.info("VPC has some issues. Please check")

        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message":"VPC Request failed with error {} ".format(str(e))})
        }


def flatten_params_dict(params):
    result  = []

    for param in params:
        if params[param] and params[param] != 'None':
            if isinstance(params[param],str):
                result.append({'ParameterKey':param,'ParameterValue':params[param]})
            elif isinstance(params[param],list):
                value = ''

                for v in params[param]:
                    value += v + ','
                value = value[:-1]

                result.append({'ParameterKey': param, 'ParameterValue': value})
            else:
                result.append({'ParameterKey': param, 'ParameterValue': str(params[param])})

    print ("flattened params {} ".format(result))
    return result


def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]


