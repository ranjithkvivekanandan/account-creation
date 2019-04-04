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


sts_client = boto3.client('sts')




def lambda_handler(event, context):
    logger.debug("Received event: %s for provisioning logs bucket", json.dumps(event))

    result = event

    new_aws_account = event['accountId']

    devops_artifact_bucket = get_mandatory_evar("DEVOPS_ARTIFACT_BUCKET")

    log_pipeline_provisioning_template_location = get_mandatory_evar("LOG_PIPELINE_CREATION_CFT_LOCATION")

    log_pipeline_provisioning_template_version = get_mandatory_evar("LOG_PIPELINE_CREATION_CFT_VERSION")



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

    cft_client = session.client('cloudformation')

    stack_name = "pac-{}-log-pipeline-provisioning".format(new_aws_account)


    try:
        describe_stack_response = cft_client.describe_stacks(StackName=stack_name)
        logger.info("describe_stack_response is {}".format(str(describe_stack_response)))
        stack = describe_stack_response['Stacks'][0]
        if stack['StackStatus'] !='DELETE_COMPLETE':
            result['logPipelineStackName'] = stack_name
            result['logPipelineAlreadyExists']= True
            if stack['StackStatus'] in ['CREATE_COMPLETE','UPDATE_COMPLETE']:
                result['provisioningLogBucketStatus'] = 'COMPLETED'
            else:
                result['provisioningLogBucketStatus'] = stack['StackStatus']
                result['instrcution'] = "Please cleanup the log pipleine stack and rerun the step."
            return result
    except Exception as e:
        logger.error(str(e))

    result['provisioningLogPipelineCFTVersion'] = log_pipeline_provisioning_template_version


    create_stack_response = cft_client.create_stack(
                    StackName= stack_name,
                    TemplateURL=log_pipeline_provisioning_template_location,
                    Parameters=[
                        {
                            'ParameterKey': 'AccountId',
                            'ParameterValue': new_aws_account
                        },
                        {
                            'ParameterKey': 'DevopsArtifactsBucket',
                            'ParameterValue': devops_artifact_bucket
                        },
                        {
                            'ParameterKey': 'LogPipelineCFTVersion',
                            'ParameterValue': log_pipeline_provisioning_template_version
                        }],
                    Capabilities=['CAPABILITY_NAMED_IAM'],
                    EnableTerminationProtection=True)

    logger.info("Create stack response is {} ".format(create_stack_response))


    time.sleep(20)

    stack_status =cft_client.describe_stacks(StackName= stack_name)

    logger.info("log bucket provisioning status is {} ".format(str(stack_status)))

    if len(stack_status['Stacks'])==0:
        raise Exception("Unable to find the log bucket stack")

    result['logPipelineStackName'] = stack_name

    status = stack_status['Stacks'][0]['StackStatus']

    if 'Outputs' in stack_status['Stacks'][0]:
        outputs = stack_status['Stacks'][0]['Outputs']


    while status == 'CREATE_IN_PROGRESS':
        time.sleep(5)
        stack_status = cft_client.describe_stacks(StackName=stack_name)
        status = stack_status['Stacks'][0]['StackStatus']
        if 'Outputs' in stack_status['Stacks'][0]:
            outputs = stack_status['Stacks'][0]['Outputs']
        logger.info("log bucket provisioning status is {} ".format(str(stack_status)))

    if status == 'CREATE_COMPLETE':
        for output in outputs:
            if output['OutputKey'] == 'BucketName':
                result['logBucket'] = output['OutputValue']
                result['provisioningLogBucketStatus'] = 'COMPLETED'
                return result

    else:
        logger.info("Creation of log bucket has some issues. Please check")
        result['provisioningLogBucketStatus'] = 'FAILED'
        return result

def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]
