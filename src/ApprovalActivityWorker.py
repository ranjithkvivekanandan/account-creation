import boto3
import logging
import json
import urlparse

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

sf_client = boto3.client('stepfunctions')

headers = {
    'Content-Type': 'application/json'
}


def lambda_handler(event, context):
    logger.debug("Received event: %s for approval activity worker api ", json.dumps(event))

    try:

        if event['resource'] == '/approve':
            params = json.loads(event['queryStringParameters']['params'])
            logger.info(str(params))
            approval_success_response = sf_client.send_task_success(
                taskToken=params['taskToken'],
                output=params['input']
            )

            logger.debug("Activity approval response {} ".format(json.dumps(approval_success_response)))

            message = "Request Approved"

        elif event['resource'] == '/reject':
            params = json.loads(event['queryStringParameters']['params'])

            approval_reject_response = sf_client.send_task_failure(
                taskToken=params['taskToken'],
                cause="Approval Rejected"
            )

            logger.debug("Activity reject response {} ".format(json.dumps(approval_reject_response)))

            message = "Request Rejected"

        else:
            raise Exception("Invalid Resource")

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({"message": message})
        }
    except Exception as e:
        logger.error(str(e))
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({"message": "Request failed: {} ".format(str(e))})
        }
