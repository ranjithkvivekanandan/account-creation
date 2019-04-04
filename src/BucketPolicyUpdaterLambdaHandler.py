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


s3_client = boto3.client('s3')

def lambda_handler(event, context):
    logger.debug("Received event: %s for devops artifact bucket policy updation", json.dumps(event))

    result = event
    result["devopsArtifactAccessStatus"] = "COMPLETED"

    return result

    new_aws_account = event['accountId']

    devops_artifact_bucket = get_mandatory_evar("DEVOPS_ARTIFACT_BUCKET")

    try:
        bucket_policy = s3_client.get_bucket_policy(Bucket=devops_artifact_bucket)['Policy']
    except Exception as ex:
        if 'NoSuchBucketPolicy' in str(ex):
            bucket_policy = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement":[]
                }
            )
        else:
            logger.error(str(ex))
            raise ex

    logger.info("Existing bucket policy for devops_artifact_bucket {} ".format(bucket_policy))

    bucket_policy =  json.loads(bucket_policy)

    additonal_policy_statement = {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::{}:root".format(new_aws_account)
                ]
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::{}/*".format(devops_artifact_bucket)
        }

    logger.info("Bucket Policy Statement for allowing new account {} ".format(json.dumps(additonal_policy_statement)))

    old_bucket_policy_statment = []

    if 'Statement' in bucket_policy:
        old_bucket_policy_statment = bucket_policy['Statement']

    old_bucket_policy_statment.append(additonal_policy_statement)

    bucket_policy['Statement']= old_bucket_policy_statment

    logger.info("New generated bucket policy {} ".format(json.dumps(bucket_policy)))

    s3_client.put_bucket_policy(Bucket=devops_artifact_bucket,Policy=json.dumps(bucket_policy))

    logger.info("Devops Artifact bucket policy has been updated")

    result["devopsArtifactAccessStatus"] = "COMPLETED"

    return result

def get_mandatory_evar(evar_name):
    if not evar_name in os.environ:
        raise RuntimeError("Missing environment variable: {}".format(evar_name))
    return os.environ[evar_name]
