from __future__ import print_function
import os
import uuid
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]

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

def get_session(role_arn, external_id=None):
    
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
                    RoleArn=role_arn,
                    DurationSeconds=900,
                    RoleSessionName="testsession_name"
                )
    print(response)
    """
    session = aws_session(
        sts_client,
        role_arn=role_arn,
        external_id=external_id,
        session_name='tools-account-test-session-'+str(uuid.uuid4())
    )
    return session
    """

def get_api_gw_url_and_key(session, stack_name):
    
    cft_client = session.client('cloudformation')
    response = cft_client.describe_stacks(StackName=stack_name)
    print(response)

def start_test(test_devops_role):

    print("Starting tests")

    """
    test_devops_session = get_session(test_devops_role)
    #get_api_gw_url_and_key(test_devops_session, 'accountcreation')
    """
    print("Ending tests")
    

if __name__ == "__main__":
    #test_devops_role = get_mandatory_evar("TEST_DEVOPS_ROLE")
    test_devops_role = 'arn:aws:iam::864556046276:role/CodePipeline-Cross-Account-Role-Access'
    #external_id = get_mandatory_evar("EXTERNAL_ID")
    start_test(test_devops_role)

