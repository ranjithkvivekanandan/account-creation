from hashlib import md5
from lib.crhelper import cfn_handler
from custom_resource_handler import ExpungeDefaultVPC
from lib.logger import Logger
import logging
import os
import inspect

#Assigning Current region
region = os.environ['AWS_DEFAULT_REGION']

# initialise logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#Lambda handler function to delete default vpc in all the regions
def lambda_handler(account_id, context):
    logger.info("<<<<<<<<<< Lambda_handler Event >>>>>>>>>>")
    logger.info(account_id)
    result = {}
    if account_id:
        input = {
          "ResourceProperties": {
            "Region": region,
            "AccountList": [
              account_id
            ]
          }
        }
            
    else:
        logger.info("Mandatory parameter accountId is missing")
        result['status'] = "Failed"
        result['reason'] = "Mandatory parameter accountId is missing"
        return result
    
    try:
        logger.info(input)
        ec2 = ExpungeDefaultVPC(input, logger)
        logger.info("Deleting VPCs and its dependencies")
        response = ec2.expunge_default_vpc()
        logger.info("Response from ExpungeVPC CR Handler")
        logger.info(response)
        result['status'] = "COMPLETED"
        result['reason'] = "Default VPC in all region deleted successfully"
        return result

    except Exception as e:
        message = {'EXCEPTION': str(e)}
        logger.exception(message)
        logger.info("Default VPC Deletion has some issues. Please check")
        print("Exception while executing delete default vpc {}".format(str(e)))
        result['status'] = "Failed"
        result['reason'] = "Exception while executing delete default vpc"
        return result