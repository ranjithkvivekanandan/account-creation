import boto3
import os
import logging
import json
import urllib

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

region = os.environ['AWS_DEFAULT_REGION']

sf_client = boto3.client('stepfunctions')

ses_client = boto3.client('ses')


def send_email(input,task_token,from_email,to_email):
    approval_api = os.environ['APPROVAL_API']
    params = json.dumps({"input": input, 'taskToken': urllib.quote(task_token, safe='')})

    approval_link = "{}/approve?params={}".format(approval_api, params)

    reject_link = "{}/reject?params={}".format(approval_api, params)

    BODY_HTML = """<html>
    <head></head>
    <body>
      <h1>AWS Account Requested For Your Email </h1>
      <p>This email was used to request a new aws account. <br> {params} <br> Click
        <a href='{approve}'>verify</a> or
          <a href='{reject}'>reject</a>
          </p>
    </body>
    </html>
                """.format(approve=approval_link, reject=reject_link, params=input)

    # The character encoding for the email.
    CHARSET = "UTF-8"

    logger.debug(" Body html is {} ".format(BODY_HTML))

    response = ses_client.send_email(
        Source=from_email,
        Destination={
            'ToAddresses': [
                to_email
            ]
        },
        Message={
            'Subject': {
                'Data': 'Email Verification request',
            },
            'Body': {
                'Html': {
                    'Data': BODY_HTML,
                    'Charset': CHARSET
                }
            }
        }
    )

    logger.debug("SES response {} ".format(json.dumps(response)))



def lambda_handler(event, context):
    logger.debug("Received event: %s for approval activity task polling ", json.dumps(event))

    email_verification_activity_arn = os.environ['EMAIL_VERIFICATION_ACTIVITY']
    from_email = os.environ['FROM_EMAIL']

    try:
        activity_response = sf_client.get_activity_task(
            activityArn=email_verification_activity_arn,
            workerName='lambda-approval-poller'
        )

        logger.debug("Email verification activity polling response {} ".format(json.dumps(activity_response)))

        if 'taskToken' in activity_response:
            logger.debug("Apporval is pending.")
            task_token = activity_response['taskToken']
            input = activity_response['input']
            parsed_input = json.loads(input)
            send_email(input,task_token,from_email,parsed_input['emailId'])
    except Exception as e:
        logger.error("Exception: {}".format(str(e)))
