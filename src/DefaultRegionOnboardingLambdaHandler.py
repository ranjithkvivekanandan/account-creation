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


def lambda_handler(event, context):
    logger.debug("Received event: %s for for default account onboarding", json.dumps(event))

    result = event

    if event['accountOnboardingStatus'] != 'COMPLETED':
        logger.info("accountOnboardingStatus is incomplete . Hence skipping this step")
        result['defaultRegionOnboardingStatus'] = 'SKIPPED'
        return result

    new_aws_account = event['accountId']

    region_onboarding_stackset = get_mandatory_evar("REGION_ONBOARDING_STACKSET")


    try:
        response = cloudformation_client.create_stack_instances(
            StackSetName=region_onboarding_stackset,
            Accounts=[
                new_aws_account
            ],
            Regions=[region
                     ])

        logger.info("Stack instance response for new account {} ".format(str(response)))

        operation_id = response['OperationId']

        status_response = cloudformation_client.describe_stack_set_operation(
            StackSetName=region_onboarding_stackset,
            OperationId=operation_id
        )

        count = 0

        while status_response['StackSetOperation']['Status']=='RUNNING':
            # Terminate the wait condition after 4 mins
            count += 1
            if count > 8:
                break
            time.sleep(30)
            status_response = cloudformation_client.describe_stack_set_operation(
                StackSetName=region_onboarding_stackset,
                OperationId=operation_id
            )

        result['accountOnboardingStatus'] = status_response['StackSetOperation']['Status']

        if status_response['StackSetOperation']['Status']=='SUCCEEDED':
            result['defaultRegionOnboardingStatus'] = 'COMPLETED'


    except Exception as e:
        logger.info("Region onboarding has some issues. Please check")
        result['defaultRegionOnboardingStatus'] = 'FAILED'

    return result


def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]
