import argparse
import uuid

import boto3
import botocore

import json, time

tags = {
    'description': 'Used by PingSafe Scanner to send scan events over webhook'
}

parser = argparse.ArgumentParser(
    prog='PingSafe Webhook Lambda App',
    description='Receive webhooks from PingSafe on AWS Lambda')

parser.add_argument('--aws-cli-profile', help='aws profile configured in your cli, if not provided picks default config',
                    default='default')
parser.add_argument('--aws-region', help='aws region name for lambda and sqs to be created',
                    required=True)
parser.add_argument('--queue-name', help='name of queue to be created for storing webhook events',
                    required=True)
parser.add_argument('--lambda-function-name', help='name of lambda function to be created',
                    required=True)

args = parser.parse_args()

aws_config = botocore.config.Config(
    region_name=args.aws_region,
    signature_version='v4',
)

session = boto3.Session(profile_name=args.aws_cli_profile)

sts = session.client('sts', config=aws_config)
user = sts.get_caller_identity()
aws_account_id = user['Account']

print(f"Using profile {args.aws_cli_profile}, with role arn {user['Arn']} to execute script")


def get_or_create_queue_url(session, queue_name):
    try:
        sqs = session.client('sqs', config=aws_config)
        try:
            queue_url = sqs.get_queue_url(QueueName=queue_name)['QueueUrl']
        except sqs.exceptions.QueueDoesNotExist:
            queue_url = sqs.create_queue(QueueName=queue_name)['QueueUrl']
        queue_attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])
        return queue_url, queue_attrs['Attributes']['QueueArn']
    except Exception as e:
        print(f"Failed to get or create queue with name {queue_name}, error:", e)
        exit(-1)


queue_url, queue_arn = get_or_create_queue_url(session, args.queue_name)


# get or create role
def generate_policy_string(region, account_id, lambda_name, queue_arn):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "logs:CreateLogGroup",
                "Resource": f"arn:aws:logs:{region}:{account_id}:*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/lambda/{lambda_name}:*"
                ]
            },
            {
                "Action": [
                    "sqs:SendMessage"
                ],
                "Effect": "Allow",
                "Resource": f"{queue_arn}"
                
            }
        ]
    }
    return json.dumps(policy)


policy_document = generate_policy_string(args.aws_region, aws_account_id, args.lambda_function_name, queue_arn)


def create_policy_roles_for_lambda(session):
    iam = session.client('iam', config=aws_config)
    identifier = str(uuid.uuid4())
    policy_name = f"PingSafeEventAWSLambdaPolicy-{identifier}"

    print(f'Creating IAM policy {policy_name}...')
    policy = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=policy_document
    )
    policy_arn = policy['Policy']['Arn']
    print(f'IAM policy {policy_arn} created successfully.')

    role_name = f"PingSafeEventAWSLambdaRole-{identifier}"
    print(f'Creating IAM role {role_name}...')
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
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
            }
        )
    )

    print(f'Attaching policy {policy_name} to role {role_name}...')
    response = iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )

    for i in range(0, 100):
        print("Waiting for policy to be attached to role...")
        time.sleep(10)
        current_role_status = iam.get_role(RoleName=role_name)
        if current_role_status['Role']['AssumeRolePolicyDocument']['Statement'][0]['Principal']['Service'] != 'lambda.amazonaws.com':
            continue
        attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        policy_attached = False
        for policy in attached_policies:
            if policy['PolicyName'] == policy_name:
                policy_attached = True
        if policy_attached:
            break

    # Confirm that the role and policy were created
    print(f'IAM role {role_name} and policy {policy_name} created successfully.')
    return role['Role']['Arn']


role_arn = create_policy_roles_for_lambda(session)


# get or create aws lambda function

def get_or_create_lamda_function(session, function_name, role_arn, path_to_code_zip, queue_url, pingsafe_api_key):
    lambda_client = session.client('lambda', config=aws_config)

    # Define the function name and runtime
    runtime = 'python3.8'

    try:
        # Get the function
        exisiting_lambda_details = lambda_client.get_function(FunctionName=function_name)
        delete_function = input(f'Function {function_name} already exists. Do you want to delete and create new function (Y/N)?')
        if delete_function == "Y":
            lambda_client.delete_function(FunctionName=function_name)
            lambda_client.delete_function_url_config(FunctionName=function_name)
        else:
            print("aborting lambda function create...")
            url_config = lambda_client.get_function_url_config(FunctionName=function_name)
            return url_config['FunctionUrl'], exisiting_lambda_details['Environment']['PINGSAFE_API_KEY']
    except lambda_client.exceptions.ResourceNotFoundException:
        print("lambda not found, creating...")

    print(f'Creating function {function_name}...')
    lambda_details = lambda_client.create_function(
        FunctionName=function_name,
        Runtime=runtime,
        Role=role_arn,
        Handler='lambda_function.lambda_handler',
        Publish=True,
        PackageType='Zip',
        Environment={
            'Variables': {
                'SQS_QUEUE_URL': queue_url,
                'PINGSAFE_API_KEY': pingsafe_api_key
            }
        },
        Code={
            'ZipFile': open(path_to_code_zip, 'rb').read()
        }
    )

    lambda_function_url = lambda_client.create_function_url_config(
        FunctionName=lambda_details['FunctionArn'],
        AuthType='NONE'
    )

    lambda_client.add_permission(
        FunctionName=function_name,
        StatementId=f"PingSafeEventsLambdaAllowPublicAccess-{str(uuid.uuid4())}",
        Action='lambda:InvokeFunctionUrl',
        Principal='*',
        FunctionUrlAuthType='NONE'
    )

    print(f'Successfully created lambda function, ')
    return lambda_function_url['FunctionUrl'], pingsafe_api_key


pingsafe_api_key = str(uuid.uuid4())

webhook_url, api_key = get_or_create_lamda_function(session, args.lambda_function_name, role_arn, 'src/deployment-package.zip', queue_url, pingsafe_api_key)

print(f"Please configure webhook on PingSafe dashboard [https://app.pingsafe.com/settings/integrations/webhook], \nenter url: {webhook_url}, api_key: {api_key}")