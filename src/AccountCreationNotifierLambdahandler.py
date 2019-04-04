from botocore.exceptions import ClientError
import boto3
from pprint import pprint
import os
import logging
import json
import time
import uuid


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#region = os.environ['AWS_DEFAULT_REGION']


sns_client = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')


def lambda_handler(event, context):
    logger.debug("Received event: %s for provisioning account onboarding", json.dumps(event))

    accounts_table = dynamodb.Table(get_mandatory_evar("ACCOUNTS_TABLE"))

    notification_topic = get_mandatory_evar("NOTIFICATION_TOPIC")
    notification_email_topic=get_mandatory_evar("NOTIFICATION_EMAIL_TOPIC")
    # Making emailId as requestId to maintain the uniqueness


    email_id = event['emailId']
    account_name= event['accountName']
    account_id= event['accountId']
    account_status= event['accountCreationStatus']
    provisioning_log_bucket_status= event['provisioningLogBucketStatus']
    account_onboarding_status= event['accountOnboardingStatus']
    region_onboarding_status= event['defaultRegionOnboardingStatus']

    message_to_publish=f'\n\nEmailId:  {email_id}\nAccountName:  {account_name}\nAccountId:  {account_id}\nAccountCreationStatus:  {account_status}\nProvisioningLogBucketStatus:  {provisioning_log_bucket_status}\nAccountOnboardingStatus:  {account_onboarding_status}\nRegionOnboardingStatus:  {region_onboarding_status}'

    event['requestId'] = email_id

    event['vpcCidrSecondOctet'] = get_vpc_cidr(email_id,accounts_table)

    accounts_table.put_item(Item = event)

    sns_client.publish(TopicArn=notification_topic, Message=json.dumps(event))

    sns_client.publish(TopicArn=notification_email_topic, Message=message_to_publish)


    return event

def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]

# Function for getting the second octet of vpc cidr

def get_vpc_cidr(email_id,accounts_table):

    account_item = accounts_table.get_item(Key={'requestId':email_id})

    if 'Item' in account_item and 'vpcCidrSecondOctet' in account_item['Item']:
        return int(account_item['Item']['vpcCidrSecondOctet'])
    else:
        account_items = accounts_table.scan()['Items']
        max_octet = 1
        for account_item in account_items:
            if 'vpcCidrSecondOctet' in account_item and int(account_item['vpcCidrSecondOctet'])>max_octet:
                max_octet = int(account_item['vpcCidrSecondOctet'])

        return  max_octet+1


