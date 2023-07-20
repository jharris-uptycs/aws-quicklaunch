#
# Uptycs account handler
# Function can be invoked direct via EventBridge Trigger or by SNS queue
# 1) New accounts trigger StackSet direct from EventBridge
# 2) Existing accounts are processed by adding them to the SNS queue. The function will take an
# instance from the topic and add a Stack instance
#
#

import json
import logging
import os
import time

import boto3
from common_functions import wait_for_stack_set_operation, \
    create_stack_set_instances, stack_set_instance_exists
from common_functions import SecretsManagerClient

VERSION = ""

# Envrironment Variables
UPTYCS_STACKSET_NAME = os.environ['UPTYCS_STACKSET_NAME']
UPTYCS_SECRET_STORE = os.environ['UPTYCS_SECRET_STORE']
UPTYCS_ACCOUNT_TOPIC = os.environ['uptycs_account_topic']
PERMISSIONS_BOUNDARY = os.environ['PERMISSIONS_BOUNDARY']
UPTYCS_ACCOUNT_NUMBER = os.environ['UPTYCS_ACCOUNT_NUMBER']
UPTYCS_ROLE_NAME = os.environ['UPTYCS_ROLE_NAME']

# Set Logging
LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def process_event_bridge(event: dict):
    """
    Handles message from EventBridge when either CreateManagedAccount or UpdateManagedAccount
    event in CloudTrail.
    Args:
        event ():
    Returns:

    """
    logger.info("Received EventBridge Event {}".format(event))

    event_details = event['detail']
    this_aws_region = event_details['awsRegion']
    srv_event_details = event_details['serviceEventDetails']

    if 'createManagedAccountStatus' in srv_event_details and \
            srv_event_details['createManagedAccountStatus']['state'] == "SUCCEEDED":
        new_account_id = srv_event_details['createManagedAccountStatus']['account']['accountId']
        logger.info(
            "Processing createManagedAccountStatus event for account: {}".format(new_account_id))
        manage_stack_instance(new_account_id, this_aws_region)
    elif 'updateManagedAccountStatus' in srv_event_details and \
            srv_event_details['updateManagedAccountStatus']['state'] == "SUCCEEDED":
        new_account_id = srv_event_details['updateManagedAccountStatus']['account']['accountId']
        logger.info(
            "Processing updateManagedAccountStatus event for account: {}".format(new_account_id))
        manage_stack_instance(new_account_id, this_aws_region)
    else:
        logger.error("Invalid event state, expected: SUCCEEDED : {}".format(event))


def manage_stack_instance(account_id: str, region: str):
    """
    Takes the account ID and region and formats them as a dict to forward to cfn_create_stack
    Args:
        account_id (): str The AWS account ID
        region (): str The AWS region
    """

    logger.info("Processing Lifecycle event for {} in {}".format(account_id, region))
    message_body = {"target_accounts": [account_id],
                    "target_regions": [region]}
    cfn_create_stack(message_body)


def cfn_create_stack(message: dict):
    """
    Takes a Json Formatted message containing AWS Account ID and creates a stack instance
    This can be called direct via manage_stack_instance() or via process_sns_notification()
    Args:
        message ():
    Example message message_body = {
        {"target_accounts": account_list, "target_regions": region_list}}

    Returns:

    """
    logger.info("Creating Stack Instance.")
    cfn_client = boto3.client("cloudformation")
    sns_client = boto3.client("sns")

    if message:
        param_accounts = message['target_accounts']
        param_regions = message['target_regions']
        logger.info("Target accounts : {}".format(param_accounts))
        logger.info("Target regions: {}".format(param_regions))

        try:
            stack_operations = True
            cfn_client.describe_stack_set(StackSetName=UPTYCS_STACKSET_NAME)
            cloud_formation_paginator = cfn_client.get_paginator(
                "list_stack_set_operations")
            stack_set_iterator = cloud_formation_paginator.paginate(
                StackSetName=UPTYCS_STACKSET_NAME
            )
            for page in stack_set_iterator:
                if "Summaries" in page:
                    for operation in page['Summaries']:
                        if operation['Status'] in ('RUNNING', 'STOPPING'):
                            stack_operations = False
                            break
                    if not stack_operations:
                        break

            if stack_operations:

                # check if stack_set_instance_exists()
                create_stack_instance_list = []
                for acct in param_accounts:
                    if not stack_set_instance_exists(UPTYCS_STACKSET_NAME, acct):
                        logger.info("adding account {} to list {}".format(acct, create_stack_instance_list))
                        create_stack_instance_list.append(acct)
                secret = SecretsManagerClient(UPTYCS_SECRET_STORE)
                params = json.loads(secret.get_secret_value())
                uptycs_account_id = UPTYCS_ACCOUNT_NUMBER
                external_id = params['external_id']
                uptycs_role_name = UPTYCS_ROLE_NAME

                if len(create_stack_instance_list) > 0:
                    response = create_stack_set_instances(UPTYCS_STACKSET_NAME,
                                                          create_stack_instance_list,
                                                          param_regions, [
                                                              {
                                                                  "ParameterKey": "UptycsAccountId",
                                                                  "ParameterValue": uptycs_account_id,
                                                                  "UsePreviousValue": False,
                                                                  "ResolvedValue": "string"
                                                              },
                                                              {
                                                                  "ParameterKey": "ExternalId",
                                                                  "ParameterValue": external_id,
                                                                  "UsePreviousValue": False,
                                                                  "ResolvedValue": "string"
                                                              },
                                                              {
                                                                  "ParameterKey": "UptycsRoleName",
                                                                  "ParameterValue": uptycs_role_name,
                                                                  "UsePreviousValue": False,
                                                                  "ResolvedValue": "string"
                                                              },
                                                              {
                                                                  "ParameterKey": "PermissionsBoundary",
                                                                  "ParameterValue": PERMISSIONS_BOUNDARY,
                                                                  "UsePreviousValue": False,
                                                                  "ResolvedValue": "string"
                                                              }

                                                          ])

                    wait_for_stack_set_operation(UPTYCS_STACKSET_NAME, response['OperationId'])
                    logger.info("Stack_set instance created {}".format(response))
                    time.sleep(10)
            else:

                logger.warning("Existing stack_set operations still running")
                message_body = {UPTYCS_STACKSET_NAME: param_accounts}
                try:
                    logger.info("Sleep and wait for 20 seconds")
                    time.sleep(20)
                    sns_response = sns_client.publish(
                        TopicArn=UPTYCS_ACCOUNT_TOPIC,
                        Message=json.dumps(message_body))

                    logger.info(
                        "Re-queued for stack_set instance creation: {}".format(sns_response))
                except Exception as sns_exception:
                    logger.error(
                        "Failed to send queue for stack_set instance creation: {}".format(
                            sns_exception))

        except Exception as describe_exception:
            logger.error("Exception getting stack set, {}".format(describe_exception))
            raise describe_exception


def process_sns_notification(sns_message: dict):
    """
    Extracts the account data payload from the SNS message and calls cfn_create_stack()
    Args:
        sns_message (): Message from SNS lambda subscription

    """
    for message in sns_message:
        json_message = json.loads(message['Sns']['Message'])
        cfn_create_stack(json_message)


def lambda_handler(event, context):
    """
    Initial handler invoked by SNS trigger or via EventBridge trigger
    process_sns_notification() will handle SNS message
    process_event_bridge() will handle EventBridge message
    Args:
        event ():
        context ():
    """
    logger.info("account.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        # called from stack_setSNS
        if 'Records' in event:
            process_sns_notification(event['Records'])
        # called from event bridge rule
        elif 'detail' in event:
            if event['detail']['eventName'] == 'CreateManagedAccount' or event['detail'][
                'eventName'] == 'UpdateManagedAccount':
                process_event_bridge(event)
        else:
            logger.info("The event is not supported.")
    except Exception as error:
        logger.error(error)
