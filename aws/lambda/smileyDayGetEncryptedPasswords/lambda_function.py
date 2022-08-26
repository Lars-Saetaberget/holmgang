import binascii
import boto3
import json

from Crypto import Random
from Crypto.Cipher import AES

parameter_store = boto3.client('ssm')


def get_parameter(parameter):
    return parameter_store.get_parameter(Name=parameter)['Parameter']['Value']


def encrypt(password, stored_password):
    key = Random.get_random_bytes(32)
    iv = Random.get_random_bytes(16)

    cipher_pass = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    cipher_stored = AES.new(key, AES.MODE_CFB, iv, segment_size=128)

    password_enc = cipher_pass.encrypt(password.encode())
    stored_password_enc = cipher_stored.encrypt(stored_password.encode())

    return binascii.hexlify(password_enc).decode(), binascii.hexlify(stored_password_enc).decode()


def lambda_handler(event, context):
    body = json.loads(event['body'])

    if body['key'] != get_parameter('smileyDay-key'):
        return {
            'statusCode': 401
        }

    password = body['password']
    stored_password = get_parameter('smileyDay-password')

    response = {}
    response['supplied_password'], response['correct_password'] = encrypt(password, stored_password)
    response['key'] = body['key']

    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }
