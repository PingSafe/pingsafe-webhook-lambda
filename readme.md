# PingSafe Webhook Lambda

### init.py
Creates AWS resources and deploys src/deployment-package.zip on lambda
AWS resources
- SQS Queue
- IAM Role and Policies required for lambda
- Lambda function 

Requirements
- aws cli
- python3

Steps to start
```shell
pip3 install -r requirements.txt
python3 init.py --aws-cli-profile <aws cli profile> --aws-region <aws region> --queue-name <sqs queue name> --lambda-function-name <lambda name>
```

In case src/lambda_function.py is changed, please add it to deployment-package.zip using
```shell
zip src/deployment-package.zip src/lambda_function.py
```