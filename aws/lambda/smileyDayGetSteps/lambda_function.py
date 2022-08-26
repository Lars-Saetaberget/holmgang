import boto3
import json

parameter_store = boto3.client('ssm')

def get_parameter(parameter):
    return parameter_store.get_parameter(Name=parameter)['Parameter']['Value']
    

def lambda_handler(event, context):
    body = json.loads(event['body'])

    if body['password'] != get_parameter('smileyDay-password'):
        return {
            'statusCode': 401
        }

    response = {}
    response = json.loads(get_parameter("smileyDay-steps"))

    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }

