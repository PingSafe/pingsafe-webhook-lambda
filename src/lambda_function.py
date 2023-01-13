import os, json, hashlib, base64

import boto3


def sha256_hash(string):
    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the bytes of the string
    sha256.update(string.encode())
    # Return the hexadecimal representation of the hash
    return sha256.hexdigest()


def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    queue_url = os.environ.get('SQS_QUEUE_URL')
    api_key = os.environ.get('PINGSAFE_API_KEY')

    try:
        if event['requestContext']['http']['method'] != "POST":
            return {
                "statusCode": 405,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "error": "Method not allowed"
                })
            }

        body = json.loads(event['body'])
        headers = event['headers']

        # verify checksum
        if 'x-pingsafe-checksum' not in headers:
            print("X-PingSafe-Checksum header cannot be found, aborting request")
            return {
                "statusCode": 401,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "error": "cannot verify request"
                })
            }

        checksum = headers['x-pingsafe-checksum']
        # For more details refer to https://docs.pingsafe.com/getting-pingsafe-events-on-custom-webhook
        if sha256_hash(f"{body['event']}.{api_key}") != checksum:
            return {
                "statusCode": 403,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "error": "checksum verification failed"
                })
            }

        event = base64.b64decode(body['event']).decode('utf-8')
        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(event)
        )
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "message": "event accepted"
            })
        }
    except Exception as e:
        print("failed to accept event, error: ", e)
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "error": "failed to accept event, please check logs for more details"
            })
        }
