import json
import logging
import os
import botocore
import boto3
import time


# Define some constants related to cfn status
SUCCESS = "SUCCESS"
FAILED = "FAILED"

# Define some states related to StackSet status
STACK_SET_SUCCESS_STATES = ["SUCCEEDED"]
STACK_SET_RUNNING_STATES = ["RUNNING", "STOPPING"]

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)

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


def is_account_active(acct):
    logger.info("aws.is_account_active called.")
    org_client = boto3.client('organizations')
    try:
        response = org_client.describe_account(
            AccountId=acct
        )
        logger.info("Account {} is {}.".format(acct, response['Account']['Status']))
        return response['Account']['Status'] == "ACTIVE"
    except Exception as describe_exception:
        logger.warning(
            "Exception getting account status on {} {}.".format(acct, describe_exception))
        return False


def get_account_id_by_name(name):
    """
    Returns the AWS Account ID from the account name
    Args:
        name (): str AWS account name

    Returns: str AWS account ID

    """
    org_client = boto3.client('organizations')
    paginator = org_client.get_paginator("list_accounts")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for acct in page['Accounts']:
            if acct['Name'] == name:
                return acct['Id']

    return None


def get_ssm_parameter(parameter_name: str, with_decrypt: bool = True):
    """
    Retrieve a JSON object from an SSM parameter.
    Args:
        parameter_name (str): The name of the SSM parameter.
        with_decrypt (bool): Parameter requires Decryption. Default is True.

    Returns:
        Dict: A dictionary containing the JSON object stored in the SSM parameter.
    """
    ssm_client = boto3.client('ssm')
    response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=with_decrypt)
    parameter_value = response['Parameter']['Value']
    return json.loads(parameter_value)


def create_stack_set_instances(stack_set_name, accounts, regions, parameter_overrides=[]):
    """
    Creates a StackSet Instance in the current account
    Args:
        stack_set_name ():
        accounts ():
        regions ():
        parameter_overrides ():

    Returns: dict Result of create_stack_instances

    """
    logger.info("common_functions.create_stack_set_instances called.")
    logger.info("Create stack name={} accounts={} regions={} parameter_overrides={} ".format(
        stack_set_name, accounts,
        regions,
        parameter_overrides))
    cloud_formation_client = boto3.client("cloudformation")
    return cloud_formation_client.create_stack_instances(StackSetName=stack_set_name,
                                                         Accounts=accounts,
                                                         Regions=regions,
                                                         ParameterOverrides=parameter_overrides,
                                                         OperationPreferences={
                                                             'RegionConcurrencyType': "PARALLEL",
                                                             'MaxConcurrentCount': 100,
                                                             'FailureToleranceCount': 999
                                                         })


def delete_stack_set_instances(config_stack_set_name, account_list, region_list):
    logger.info("common_functions.delete_stack_set_instances called.")
    try:
        cloud_formation_client = boto3.client("cloudformation")
        response = cloud_formation_client.delete_stack_instances(
            StackSetName=config_stack_set_name,
            Accounts=account_list,
            Regions=region_list,
            RetainStacks=False)
        logger.info(response)

        wait_for_stack_set_operation(config_stack_set_name, response['OperationId'])
    except Exception as delete_exception:
        logger.warning("Failed to delete stack instances: {} {} {} {}".format(config_stack_set_name,
                                                                              account_list,
                                                                              region_list,
                                                                              delete_exception))


def wait_for_stack_set_operation(stack_set_name, operation_id):
    logger.info("common_functions.wait_for_stack_set_operation called.")
    logger.info("Waiting for StackSet Operation {} on StackSet {} to finish".format(operation_id,
                                                                                    stack_set_name))
    cfn_client = boto3.client("cloudformation")
    finished = False
    status = ""
    count = 6
    while not finished:
        time.sleep(count * 20)
        status = \
            cfn_client.describe_stack_set_operation(StackSetName=stack_set_name,
                                                    OperationId=operation_id)["StackSetOperation"][
                "Status"]
        if status in STACK_SET_RUNNING_STATES:
            logger.info("{} {} still running.".format(stack_set_name, operation_id))
        else:
            finished = True
        count += 1

    logger.info("StackSet Operation finished with Status: {}".format(status))
    if status not in STACK_SET_SUCCESS_STATES:
        return False
    else:
        return True


def stack_set_exists(stack_set_name: str):
    """
    Checks for the existence of the named StackSet
    Args:
        stack_set_name (): str

    Returns: bool True if the StackSet exists

    """
    logger.info("common_functions.stack_set_exists called.")
    try:
        cfn_client = boto3.client("cloudformation")
        stack_set_result = cfn_client.describe_stack_set(
            StackSetName=stack_set_name,
        )

        logger.info("stack_set_result: {}".format(stack_set_result))
        return True
    except Exception as error:
        logger.error("Error describing Stack Set: {}.".format(error))
        return False


def stack_set_instance_exists(stack_set_name: str, account_id: str):
    """
    Checks if there are any instances of the named StackSet
    Args:
        stack_set_name (): str The StackSet Name
        account_id (): str The AWS Account Id

    Returns: bool True if a Stack Instance exists

    """
    logger.info("common_functions.stack_set_instance_exists called.")
    try:
        cfn_client = boto3.client("cloudformation")
        stack_set_result = cfn_client.list_stack_instances(
            StackSetName=stack_set_name,
            StackInstanceAccount=account_id,
        )
        if stack_set_result and "Summaries" in stack_set_result:
            stack_set_list = stack_set_result['Summaries']
            while "NextToken" in stack_set_result:
                stack_set_result = cfn_client.list_stack_set_instance(
                    NextToken=stack_set_result['NextToken']
                )
                stack_set_list.append(stack_set_result['Summaries'])

            logger.info(
                "Found {} instances of StackSet {}.".format(len(stack_set_list), account_id))
            return len(stack_set_list) > 0
        else:
            return False
    except Exception as error:
        logger.error("Got error {} listing stack instances .".format(error))
        return False


def send_cfn_fail(event, context, msg):
    """
    Initial handling of cfn failure messages
    Args:
        event (): dict The event data from initial cfn trigger
        context (): The context from the initial cfn trigger
        msg (): str The failure message to be added to the failure message dict
    """
    logger.error(msg)
    send_cfn_response(event, context, FAILED, {"Message": msg})


def send_cfn_success(event, context):
    """
    Initial handling of cfn success messages
    Args:
        event (): dict The event data from initial cfn trigger
        context (): The context from the initial cfn trigger
        msg (): str The success message to be added to the failure message dict
    """
    send_cfn_response(event, context, SUCCESS, {"Message": "SUCCESS"})


def send_cfn_response(event, context, response_status, response_data, physical_resource_id=None,
                      no_echo=False,
                      reason=None):
    """
    Args:
        event (): dict The event data from initial cfn trigger
        context (): The context from the initial cfn trigger
        response_status (): "SUCCESS" or "FAILURE" from handler
        response_data (): dict Response message from handler
        physical_resource_id ():
        no_echo ():
        reason ():
    """
    response_url = event['ResponseURL']

    logger.info(response_url)

    response_body = {
        'Status': response_status,
        'Reason': reason or "See the details in CloudWatch Log Stream: {}".format(
            context.log_stream_name),
        'PhysicalResourceId': physical_resource_id or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': no_echo,
        'Data': response_data
    }

    json_response_body = json.dumps(response_body)

    logger.info("Response body: {}".format(json_response_body))

    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }

    try:
        response = requests.put(response_url, headers=headers, data=json_response_body)
        logger.info("CFN response status code: {}".format(response.status_code))

    except Exception as error:
        logger.error("Error sending cfn response {}".format(error))


def iam_role_exists(role_name):
    """
    Determines if an IAM exists
    Args:
        role_name (): str IAM Role Name

    Returns: bool True if the role exists
    """
    iam_client = boto3.client('iam')

    try:
        iam_client.get_role(RoleName=role_name)
        logger.info("Role {} exists".format(role_name))
        return True
    except iam_client.exceptions.NoSuchEntityException:
        logger.info("Role {} does not exist".format(role_name))
        return False


def read_template_from_s3(s3_bucket: str, key: str) -> json:
    """
    Reads a cloudformation template from S3 (template in json format
    Args:
        s3_bucket ():
        key ():

    Returns:

    """
    s3_client = boto3.client("s3")
    bucket_name = s3_bucket
    member_acct_file_key = key

    # Download the template file from S3 to local
    try:
        # Get the object from S3
        s3_object = s3_client.get_object(Bucket=bucket_name, Key=member_acct_file_key)
        # Get the body of the object
        s3_object_body = s3_object['Body'].read()
        # Convert bytes to string
        s3_object_body_string = s3_object_body.decode('utf-8')
        # Convert string to JSON
        member_acct_body_json = json.loads(s3_object_body_string)
        return member_acct_body_json
    except Exception as error:
        logger.info("Exception accessing file {}".format(error))


def create_stack(stack_name: str, template_data: str, params: dict):
    cfn_client = boto3.client('cloudformation')
    """
    Creates a cloudformation stack instance
    """

    try:

        response = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_data,
            Parameters=params,
            DisableRollback=False,
            TimeoutInMinutes=2
        )

        # we expect a response, if its missing on non 200 then show response
        if 'ResponseMetadata' in response and \
                response['ResponseMetadata']['HTTPStatusCode'] < 300:
            logger.info("succeed. response: {0}".format(json.dumps(response)))
        else:
            logger.info(
                "There was an Unexpected error. response: {}".format(json.dumps(response)))

    except ValueError as error:
        logger.info("Value error caught: {}".format(error))
    except botocore.exceptions.ClientError as error:
        logger.info("Boto client error caught: {}".format(error))
    except Exception as error:
        logger.info("General Exception: {}".format(error))
