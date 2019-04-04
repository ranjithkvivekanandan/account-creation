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

def aws_session(client, role_arn=None, external_id=None, session_name='my_session'):
    logger.info("Creating session from sts assume role")
    try:
        if role_arn:
            if external_id:
                response = client.assume_role(
                    RoleArn=role_arn,
                    ExternalId=external_id,
                    DurationSeconds=900,
                    RoleSessionName=session_name
                )
            else:
                response = client.assume_role(
                    RoleArn=role_arn,
                    DurationSeconds=900,
                    RoleSessionName=session_name
                )

            session = boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
            )
            return session
        logger.info("Session created using assume role")
    except Exception as e:
        logger.info(str(e))
        raise e


# New account creation function
def create_account(aws_org_client, email,account_name,role_name,billing_access="ALLOW"):
    logger.info('Creating New account')
    try:
        response = aws_org_client.create_account(
            Email=email,
            AccountName=account_name,
            RoleName=role_name,
            IamUserAccessToBilling=billing_access
        )

        return response['CreateAccountStatus']['Id']

    except ClientError as e:
        logger.info(str(e))
        raise e


# New account creation status
def account_creation_status(aws_org_client, id):
    account_id = ''
    status = 'IN_PROGRESS'
    try:
        while status == 'IN_PROGRESS':
            status_response = aws_org_client.describe_create_account_status(
                CreateAccountRequestId=id
            )
            logger.info("Create account status " + str(status_response))
            status = status_response['CreateAccountStatus']['State']
            print(status)

        if status == "SUCCEEDED":
            account_id = status_response['CreateAccountStatus']['AccountId']
        elif status == "FAILED":
            reason = status_response['CreateAccountStatus']['FailureReason']
            logger.info("Account creation failed: " + reason)
            raise Exception(reason)

        return status, account_id

    except Exception as e:
        logger.error(str(e))
        raise e


def sts_policy():
    local_session = boto3.Session()
    devops_account_id = local_session.client('sts').get_caller_identity()['Account']
    arn = "arn:aws:iam::" + devops_account_id + ":root"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": arn
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    return trust_policy


def create_devops_trusted_role(client, role_name):
    print("Creating devOps role in the new account")
    trust_policy = sts_policy()
    try:
        role_response = client.create_role(
            Path='/',
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='DevOps account cross account role'
        )

        if role_response:
            try:
                policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
                response = client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy_arn
                )

            except Exception as e:
                print(str(e))
                raise
        result = role_response['Role']['Arn']
        print('Cross Account Role Arn created in new account')
        print(result)

        return result
    except Exception as e:
        print(str(e))
        logger.info(str(e))
        raise e

def create_account_alias(iam_client, alias, account_id):
    try:
        response = iam_client.create_account_alias(AccountAlias=alias)
        logger.info(str("Account alias set as {} for {}".format(alias, account_id)))
    except Exception as e:
        logger.info(str("Not able to set account alias for the account {}".format(account_id)))


def lambda_handler(event, context):
    logger.debug("Received event: %s for Account Creation", json.dumps(event))

    result = event

    allow_account_creation = get_mandatory_evar("ALLOW_ACCOUNT_CREATION")
    if allow_account_creation=='false':
        logger.info("allow_account_creation flag is false. hence sckipping the account creation")
        test_account_id = get_mandatory_evar("TEST_ACCOUNT_ID")
        aws_org_default_role = "pac-master-role"
        aws_org_role_arn = "arn:aws:iam::{}:role/{}".format(test_account_id,aws_org_default_role)
        devops_role_arn = "arn:aws:iam::{}:role/{}".format(test_account_id,'pac-devops')
        result['accountId'] = test_account_id
        result['awsOrgRoleArn'] = aws_org_role_arn
        result['devopsRoleArn'] = devops_role_arn
        result['accountCreationStatus'] = 'COMPLETED'
        return result


    external_id = get_mandatory_evar("MASTER_ACCOUNT_EXTERNAL_ID")
    master_account_role_arn = get_mandatory_evar("MASTER_ACCOUNT_ROLE_ARN")

    if 'emailId' not in event or 'accountName' not in event:
        raise Exception("Invalid params passed to account creation API")

    email = event["emailId"]
    account_name = event["accountName"]

    sts_client = boto3.client('sts')
    master_account_session = aws_session(
        sts_client,
        role_arn=master_account_role_arn,
        external_id=external_id,
        session_name='devops-account-session-'+str(uuid.uuid4())
    )
    aws_org_client = master_account_session.client('organizations')
    aws_org_default_role = "pac-master-role"
    account_creation_request_id = create_account(aws_org_client,email,account_name,aws_org_default_role)
    time.sleep(5)

    if account_creation_request_id:
        status_response, new_account_id = account_creation_status(aws_org_client, account_creation_request_id)
        if status_response == "SUCCEEDED":
            aws_org_role_arn = "arn:aws:iam::{}:role/{}".format(new_account_id,aws_org_default_role)
            logger.info('default role in new account {}'.format(aws_org_role_arn))
            time.sleep(10)
            sts_client = master_account_session.client('sts')
            result['accountId'] = new_account_id
            result['awsOrgRoleArn'] = aws_org_role_arn
            result['accountCreationStatus'] = 'INCOMPLETE'
            try:
                new_account_session = aws_session(
                    sts_client,
                    role_arn=aws_org_role_arn,
                    session_name='master-account-session-'+str(uuid.uuid4())
                )
                # creating iam client for the newly created account
                new_account_iam_client = new_account_session.client("iam")
                # creating devops role into the new account
                devops_role = "pac-devops"
                devops_role_arn = create_devops_trusted_role(new_account_iam_client,devops_role)
                logger.info(str(" Devops role created in new account. Arn: {} ".format(devops_role_arn)))
                create_account_alias(new_account_iam_client, account_name, new_account_id)

                logger.info("Account " + new_account_id + " created successfully")

                result['devopsRoleArn'] = devops_role_arn
                result['accountCreationStatus'] = 'COMPLETED'

            except Exception as e:
                result['errorMessage'] = str(e)

            return result

def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]

