#
# Uptycs Control Tower Initial account registration script.
# Creates the StackSet containing the Uptycs IAM Role
#
#
import json
import boto3
import logging
import os
import cfnresponse
import urllib3
import base64
import hashlib
import hmac
import datetime
import urllib.request
import urllib.error
import urllib.parse
from common_functions import SecretsManagerClient

http = urllib3.PoolManager()

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)

UPTYCS_SECRET_STORE = os.environ['UPTYCS_SECRET_STORE']

class SecretsManagerClient:
    def __init__(self, secret_name: str):
        self.secrets_client = boto3.client('secretsmanager')
        self.secret_name = secret_name

    def create_or_update_secret(self, secret_value: str) -> dict:
        try:
            response = self.secrets_client.create_secret(
                Name=self.secret_name,
                SecretString=secret_value
            )
        except self.secrets_client.exceptions.ResourceExistsException:
            response = self.secrets_client.update_secret(
                SecretId=self.secret_name,
                SecretString=secret_value
            )

        return response

    def delete_secret(self) -> dict:
        response = self.secrets_client.delete_secret(
            SecretId=self.secret_name,
            ForceDeleteWithoutRecovery=True
        )
        return response

    def get_secret_value(self) -> str:
        """
        Retrieve the value of the secret.

        Returns:
            str: The value of the secret.
        """
        response = self.secrets_client.get_secret_value(
            SecretId=self.secret_name
        )
        secret_value = response['SecretString']
        return secret_value


# def get_ssm_parameter(parameter_name: str, with_decrypt: bool = True) -> object:
#     """
#     Retrieve a JSON object from an SSM parameter.
#     Args:
#         parameter_name (str): The name of the SSM parameter.
#         with_decrypt (bool): Parameter requires Decryption. Default is True.
#
#     Returns:
#         Dict: A dictionary containing the JSON object stored in the SSM parameter.
#     """
#     ssm_client = boto3.client('ssm')
#     response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=with_decrypt)
#     parameter_value = response['Parameter']['Value']
#     return json.loads(parameter_value)


def get_uptycs_internal_id(url, req_header, account_id):
    # params = {"hideServices": "true", "hideSideQuery": "false", "minimalInfo": "true"}

    try:
        status, response = http_get(url, req_header)
        if status == 200:
            for item in response['items']:
                if item['orgId'] == get_org_id():
                    uptycs_org_id = response['items'][0]['id']
                    return uptycs_org_id
                else:
                    logger.info('Failed to find Uptycs Org ID')
                    return
        else:
            return
    except Exception as error:
        logger.info("Error getting uptycs internal id for org")
        return


def remove_illegal_characters(input_string):
    return input_string.replace('=', '').replace('+', '-').replace('/', '_')


def base64_object(input_object):
    input_bytes = json.dumps(input_object).encode('utf-8')
    base64_bytes = base64.b64encode(input_bytes)
    base64_string = base64_bytes.decode('utf-8')
    output = remove_illegal_characters(base64_string)
    return output

def create_auth_token(key, secret):
    date = int(datetime.datetime.now().timestamp())
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'iss': key, 'iat': date, 'exp': date + 60}  # Token expires in 60 seconds
    unsigned_token = base64_object(header) + '.' + base64_object(payload)
    signature_hash = hmac.new(secret.encode('utf-8'), unsigned_token.encode('utf-8'),
                              hashlib.sha256)
    signature = base64.b64encode(signature_hash.digest()).decode('utf-8')
    return unsigned_token + '.' + remove_illegal_characters(signature)

def http_post(url, headers, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def http_delete(url, headers):
    req = urllib.request.Request(url, headers=headers, method='DELETE')
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.msg
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def http_get(url, headers, params=None):
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def deregister_account(url, header, account_id):
    deregister_url = f"{url}/{account_id}"
    status, response = http_delete(deregister_url, header)
    if status == 200:
        return (response)

def get_org_id():
    org_client = boto3.client('organizations')
    resp = org_client.describe_organization()
    return resp['Organization']['Id']


def get_master_account():
    try:
        org_client = boto3.client('organizations')
        resp = org_client.describe_organization()
        return resp['Organization']['MasterAccountId']
    except Exception as error:
        logger.info('Error getting master account id {}'.format(error))

def lambda_handler(event, context):
    logger.info("Got event {}".format(event))
    role_name = event['ResourceProperties']['role_name']
    ctaccount = event['ResourceProperties']['ctaccount']
    ctprefix = event['ResourceProperties']['ctprefix']
    ctbucket = event['ResourceProperties']['ctbucket']
    ctregion = event['ResourceProperties']['ctregion']
    account_id = get_master_account()
    secret =  SecretsManagerClient(UPTYCS_SECRET_STORE)
    uptycs_api_params = json.loads(secret.get_secret_value())
    domain = uptycs_api_params.get('domain')
    domainSuffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    external_id = uptycs_api_params.get('external_id')
    logger.info("Initial event received {}".format(event))
    token = create_auth_token(key, secret)
    req_header = {
        'Authorization': f"Bearer {token}",
        'date': datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        'Content-type': "application/json"
    }
    uptycs_api_url = f"https://{domain}{domainSuffix}/public/api/customers/{customer_id}/cloud/aws/organizations"
    response_data = {}
    try:
        if "RequestType" in event:
            # Handle create event
            if event["RequestType"] == "Create":
                try:
                    req_payload = {
                            "deploymentType": "uptycs",
                            "accessConfig": {},
                            "organizationId": account_id,
                            "integrationName": role_name,
                            "awsExternalId": external_id,
                            "buckets": [
                                {
                                    "bucketAccount": ctaccount,
                                    "bucketPrefix": ctprefix,
                                    "bucketName": ctbucket,
                                    "bucketRegion": ctregion
                                }
                            ],
                            "kinesisStream": {}
                        }

                    status, response = http_post(uptycs_api_url, req_header, req_payload)
                    if 200 == status:
                        logger.info('Successfully integrated AWS account {}'.format(account_id))
                        response_data['Message'] = f"Account {account_id} created successfully"
                        cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
                    else:
                        logger.info("Error - {} Message {}".format(status,
                                                                   response["error"]["message"][
                                                                       "detail"]))
                        response_data['Message'] = response["error"]["message"]["detail"]
                        cfnresponse.send(event, context, cfnresponse.FAILED, response_data)
                except Exception as error:
                    logger.info("Error during create event {}".format(error))
                    cfnresponse.send(event, context, cfnresponse.FAILED, response_data)
            # Handle delete event
            elif event["RequestType"] == "Delete":
                try:
                    account_id = get_master_account()
                    uptycs_account_id = get_uptycs_internal_id(uptycs_api_url, req_header,
                                                               account_id)
                    if uptycs_account_id:
                        resp = deregister_account(uptycs_api_url, req_header, uptycs_account_id)
                        if resp == 'OK':
                            logger.info('Successfully deleted AWS account {}'.format(
                                account_id))
                            response_data['Message'] = f"Account {account_id} deleted successfully"

                    else:
                        logger.info('No entry found for AWS account {}'.format(account_id))
                        response_data['Message'] = f"Account {account_id} not found"
                except Exception as error:
                    logger.info("Error during Delete event {}".format(error))
                    response_data[f"Exception handling delete event {error}"]
                finally:
                    cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
            # Handle update event
            elif event["RequestType"] == "Update":
                response_data['Nothing to do for update event']
                cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
        # Handle unknown event
        else:
            logger.info("Unknown event")
            response_data[f"Got event {event['RequestType']}"]
            cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
    except Exception as Error:
        response_data[f'Got exception {Error}']
        logger.info("Unknown event type")
        cfnresponse.send(event, context, cfnresponse.FAILED, response_data)



