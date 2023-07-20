#
# Uptycs Control Tower Initial setup script.
# Creates the StackSet containing the Uptycs IAM Role
#
#
VERSION = ""
import json
import logging
import os
import boto3
import urllib3
from crhelper import CfnResource

from common_functions import send_cfn_fail, send_cfn_success, \
    delete_stack_set_instances, iam_role_exists, is_account_active, get_account_id_by_name, \
    create_stack_set_instances, wait_for_stack_set_operation, read_template_from_s3, create_stack

http = urllib3.PoolManager()

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)

# StackSet names from Env variables
UPTYCS_ROLE_NAME = os.environ['UPTYCS_ROLE_NAME']
UPTYCS_POLICY_FILE = os.environ['UPTYCS_POLICY_FILE']
UPTYCS_S3_BUCKET = os.environ['UPTYCS_S3_BUCKET']

UPTYCS_SECRET_STORE = os.environ['UPTYCS_SECRET_STORE']
UPTYCS_ACCOUNT_MGT_TOPIC = os.environ['UPTYCS_ACCOUNT_MGT_TOPIC']
EXISTING_ACCOUNTS = os.environ['EXISTING_ACCOUNTS']
UPTYCS_MEMBER_ACCOUNT_TEMPLATE_NAME = os.environ['UPTYCS_MEMBER_ACCOUNT_TEMPLATE_NAME']
UPTYCS_LOG_ACCOUNT_TEMPLATE_NAME = os.environ['UPTYCS_LOG_ACCOUNT_TEMPLATE_NAME']

# Constants associated with Log Archive account
UPTYCS_ACCOUNT_NUMBER = os.environ['UPTYCS_ACCOUNT_NUMBER']
CLOUDTRAIL_BUCKET_NAME = os.environ['CLOUDTRAIL_BUCKET_NAME']
KMS_KEY_ARN = os.environ['KMS_KEY_ARN']
PERMISSIONS_BOUNDARY = os.environ['PERMISSIONS_BOUNDARY']

UPTYCS_LOG_ACCT_STACKSET_NAME = 'Uptycs-Log-Archive-Integration-StackSet'
LOG_ACCOUNT_NAME = 'Log archive'
UPTYCS_STACKSET_NAME = 'Uptycs-Integration-StackSet'


helper = CfnResource(json_logging=False, log_level="INFO",
                     boto_level="CRITICAL", sleep_on_delete=15)

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

def lambda_handler(event, context):
    """
    Initial lambda handler called from cloudformation custom resource handler
    Script performs an initial setup
    Args:
        event ():
        context ():

    Returns:

    """
    logger.info("Initial event received {}".format(event))
    try:
        if "RequestType" in event:
            helper(event, context)
    except Exception as Error:
        logger.info("Unknown event type")
        helper.init_failure(Error)


@helper.create
@helper.update
def create(event, context):
    """
    Initial create/update handler that manages the creation or deletion of the Uptycs StackSet
    Args:
        event ():
        context ():

    Returns: Valid CFN response

    """

    # Get Account ID from lambda function arn in the context
    management_account_id = context.invoked_function_arn.split(":")[4]
    # Get Region from lambda function arn in the context
    region_name = context.invoked_function_arn.split(":")[3]
    stack_set_admin_role = "arn:aws:iam::" + management_account_id + ":role/service-role" \
                                                                     "/AWSControlTowerStackSetRole"
    stack_set_execution_role = "AWSControlTowerExecution"

    try:
        params = json.loads(SecretsManagerClient(UPTYCS_SECRET_STORE).get_secret_value())
        logger.info("Got uptycs secrets")
        uptycs_account_id = UPTYCS_ACCOUNT_NUMBER
        external_id = params['external_id']
        uptycs_role_name = UPTYCS_ROLE_NAME
        # Create the Uptycs Read Only Role StackSet for member accounts
        member_acct_template_body = read_template_from_s3(UPTYCS_S3_BUCKET,
                                                       UPTYCS_MEMBER_ACCOUNT_TEMPLATE_NAME)
        member_acct_params = [
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

        ]
        # Create Uptycs Read Only Role in this account
        if not iam_role_exists(UPTYCS_ROLE_NAME):
            logger.info("Uptycs Read Only Role does not exist...Creating")
            create_stack('Uptycs-Integration',json.dumps(member_acct_template_body), member_acct_params)

        # Create a StackSet in this account
        handle_stackset_creation(stack_set_admin_role, stack_set_execution_role,
                                 json.dumps(member_acct_template_body), UPTYCS_STACKSET_NAME,
                                 region_name,
                                 member_acct_params)

        log_acct_params = [
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
                "ParameterKey": "KMSKeyArn",
                "ParameterValue": KMS_KEY_ARN,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            },
            {
                "ParameterKey": "CloudTrailBucketName",
                "ParameterValue": CLOUDTRAIL_BUCKET_NAME,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            },
            {
                "ParameterKey": "PermissionsBoundary",
                "ParameterValue": PERMISSIONS_BOUNDARY,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            }

        ]
        log_acct_template_body = read_template_from_s3(UPTYCS_S3_BUCKET,
                                                       UPTYCS_LOG_ACCOUNT_TEMPLATE_NAME)
        # Create the Uptycs Read Only Role StackSet for Log Archive account
        handle_stackset_creation(stack_set_admin_role, stack_set_execution_role,
                                 json.dumps(log_acct_template_body), UPTYCS_LOG_ACCT_STACKSET_NAME,
                                 region_name, log_acct_params)
        create_log_account_stack_instance(LOG_ACCOUNT_NAME, region_name)

    except Exception as create_exception:
        send_cfn_fail(event, context, "Setup failed {}.".format(create_exception))
        return None

    send_cfn_success(event, context)
    return None


@helper.delete  # crhelper method to delete stack set and stack instances
def delete(event, context):
    """
    Handles the deletion of the StackSet and Stack instances
    """
    cloudformation_client = boto3.client("cloudformation")
    region_name = context.invoked_function_arn.split(":")[3]
    try:
        paginator = cloudformation_client.get_paginator("list_stack_instances")
        page_iterator = paginator.paginate(StackSetName=UPTYCS_STACKSET_NAME)
        stack_set_list = []
        account_list = []
        region_list = [region_name]
        for page in page_iterator:
            if "Summaries" in page:
                stack_set_list.extend(page["Summaries"])
        for instance in stack_set_list:
            acct = instance["Account"]
            region = instance["Region"]
            try:
                if is_account_active(acct):
                    logger.info("Found stack instance in account {}".format(acct))
                    account_list.append(acct)
                    region_list.append(region)
                    logger.info("Adding acct {}".format(acct))
                else:
                    logger.info("Skipping acct {}".format(acct))
            except Exception as account_status_exception:
                logger.warning("Account status exception for acct {} {}".format(acct,
                                                                                account_status_exception))

        region_list = list(set(region_list))
        account_list = list(set(account_list))
        logger.info("StackSet instances found in region(s): {}".format(region_list))
        logger.info("StackSet instances found in account(s): {}".format(account_list))

        if len(account_list) > 0:
            logger.info("Found stack instances from accounts {}".format(account_list))
            delete_stack_set_instances(UPTYCS_STACKSET_NAME, account_list, region_list)

    except Exception as stack_instance_exception:
        logger.info("Error {} deleting stackinstances".format(stack_instance_exception))

    try:
        response = cloudformation_client.delete_stack_set(StackSetName=UPTYCS_STACKSET_NAME)
        logger.info("StackSet {} template delete status {}".format(UPTYCS_STACKSET_NAME,
                                                                   response))
    except Exception as stack_set_exception:
        logger.warning("Problem occurred while deleting, StackSet {} still exist : {}".format(
            UPTYCS_STACKSET_NAME,
            stack_set_exception))
    send_cfn_success(event, context)
    return None


def handle_stackset_creation(stack_set_admin_role: str, stack_set_execution_role: str,
                             template_body: str, stack_set_name: str, region_name: str,
                             params_list: list):
    """
    Checks for an existing StackSet and creates it if it does not exist
    Args:
        stack_set_admin_role (): str StackSet Administration Role Arn
        stack_set_execution_role (): str Name of the Execution Role
        template_url (): str StackSet Template URL
        stack_set_name (): str Name of the StackSet
        region_name (): str AWS Region Name

    Returns:

    """
    cfn_client = boto3.client("cloudformation")
    try:
        cfn_client.describe_stack_set(StackSetName=stack_set_name)
        logger.info("Stack set {} already exist".format(stack_set_name))
    except Exception as describe_exception:
        # StackSet does not exist so create it.
        logger.info(
            "Stack set {} does not exist, creating it now".format(stack_set_name))
        logger.info("Creating StackSet {} ".format(stack_set_name))

        cfn_client.create_stack_set(
            StackSetName=stack_set_name,
            Description="Uptycs StackSet",
            TemplateBody=template_body,
            Parameters=params_list,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            AdministrationRoleARN=stack_set_admin_role,
            ExecutionRoleName=stack_set_execution_role)

        try:
            cfn_client.describe_stack_set(StackSetName=stack_set_name)
            logger.info("StackSet {} deployed".format(stack_set_name))
        except cfn_client.exceptions.StackSetNotFoundException as describe_exception:
            logger.info("Failed to crete StackSet {}".format(stack_set_name))
        if EXISTING_ACCOUNTS == "Yes":
            #
            # Create Stack Instances in all existing member accounts except the log
            # archive and audit accounts
            #
            logger.info("Pushing to existing member accounts")
            try:
                # Get the log account id as this requires a different template
                log_account_id = get_account_id_by_name(LOG_ACCOUNT_NAME)
                # All member accounts under StackSet management will receive Baseline stackset
                # Use this list to determine the list of accounts under management
                # Use this list instead of all accounts if some accounts are integrated for billing
                # only
                control_tower_baseline_stack = "AWSControlTowerBP-BASELINE-ROLES"
                account_set = set()
                # Create a reusable Paginator
                paginator = cfn_client.get_paginator('list_stack_instances')
                # Create a PageIterator from the Paginator
                page_iterator = paginator.paginate(StackSetName=control_tower_baseline_stack)


                for page in page_iterator:
                    for inst in page['Summaries']:
                        if inst['Region'] == region_name and inst['Status'] == 'CURRENT':
                            if inst['Account'] != log_account_id:
                                account_set.add(inst['Account'])
                account_list = list(account_set)
                logger.info(
                    'These are the accounts that require the stackset {}'.format(account_list))
                if len(account_list) > 0:
                    logger.info("Sending these accounts to SNS {}".format(account_list))
                    send_to_sns_topic(account_list, [region_name])
            except Exception as exception:
                logger.info("Got exception {} creating stackset".format(exception))
        else:
            logger.info("Chose NOT to deploy to existing accounts.")


def send_to_sns_topic(account_list: list, region_list: list):
    """
        Args:
        account_list (): List of AWS accounts
        region_list ():  List of AWS regions

    Returns:

    """
    sns_client = boto3.client("sns")

    message_body = {"target_accounts": account_list, "target_regions": region_list}
    logger.info("Publish message {} to SNS".format(message_body))
    try:
        sns_response = sns_client.publish(
            TopicArn=UPTYCS_ACCOUNT_MGT_TOPIC,
            Message=json.dumps(message_body))

        logger.info("Queued for stackset instance creation: {}".format(sns_response))
    except Exception as sns_exception:
        logger.info("Exception {} writing to SNS topic".format(sns_exception))


def create_uptycs_role(s3_object_key: str, bucket_name, role_name: str):
    """
    Creates an Uptycs role in the master account from an policy file in an s3 bucket
    Args:
        s3_object_key ():
        bucket_name ():
        role_name ():

    Returns: bool

    """
    try:
        # Create IAM client and S3 client
        iam_client = boto3.client('iam')
        s3_client = boto3.client('s3')

        # Define role name
        role_name = role_name

        # Read policy from S3 bucket
        response = s3_client.get_object(Bucket=bucket_name, Key=s3_object_key)
        policy_document = json.loads(response['Body'].read())
        print(policy_document)
        # Create IAM role
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }),
        )

        # Attach policy to IAM role
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='Uptycs-Access',
            PolicyDocument=json.dumps(policy_document),
        )
        logger.info("Created role {}".format(role_name))
        return True
    except Exception as error:
        logger.info("Create role error {}".format(error))
        return


def create_log_account_stack_instance(log_account_name: str, region_name: str):
    """
    Create a CFT Stack instance in the Control Tower log archive account
    Args:
        log_account_name ():
        region_name ():

    Returns:

    """
    try:
        log_account_id = get_account_id_by_name(LOG_ACCOUNT_NAME)
        params = json.loads(SecretsManagerClient(UPTYCS_SECRET_STORE).get_secret_value())
        logger.info("Got API keys")
        uptycs_account_id = UPTYCS_ACCOUNT_NUMBER
        external_id = params['external_id']
        uptycs_role_name = UPTYCS_ROLE_NAME
        response = create_stack_set_instances(UPTYCS_LOG_ACCT_STACKSET_NAME,
                                              [log_account_id],
                                              [region_name], [
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
                                                      "ParameterKey": "KMSKeyArn",
                                                      "ParameterValue": KMS_KEY_ARN,
                                                      "UsePreviousValue": False,
                                                      "ResolvedValue": "string"
                                                  },
                                                  {
                                                      "ParameterKey": "CloudTrailBucketName",
                                                      "ParameterValue": CLOUDTRAIL_BUCKET_NAME,
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

        # wait_for_stack_set_operation(UPTYCS_STACKSET_NAME, response['OperationId'])
        logger.info("Stack_set instance created {}".format(response))

    except Exception as error:
        logger.info("Error creating log account stack instance {}".format(error))

