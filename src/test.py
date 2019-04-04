import boto3
import os

cft = boto3.client('cloudformation','us-west-2')

try:

    #describe_stack_response = cft.describe_stacks(StackName='dev-dl')

    #print(str(describe_stack_response))

    os.environ["flag"] = False

    if os.environ["flag"]:
        print("false")

except Exception as e:
    if 'does not exist' in str(e):
        print("Stack is missing")