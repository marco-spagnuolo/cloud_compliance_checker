# Cloud Compliance Checker

This project implements compliance checks for cloud environments using AWS Config and AWS Systems Manager. It aligns with the NIST 800-171 framework, specifically focusing on Configuration Management (CM).

## Prerequisites

Before you begin, ensure you have the following:

1. **AWS Account**: You need an AWS account to use AWS Config and AWS Systems Manager.
2. **AWS CLI**: Install the AWS Command Line Interface (CLI) from [AWS CLI installation guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).
3. **AWS SDK for Go**: Ensure you have the AWS SDK for Go installed. You can find installation instructions [here](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/welcome.html).

## Setup Guide

### Step 1: Set Up AWS Config

AWS Config continuously monitors and records your AWS resource configurations and allows you to automate the evaluation of recorded configurations against desired configurations.

1. **Enable AWS Config via AWS Management Console**:
   - Sign in to the AWS Management Console and open the AWS Config console at [AWS Config Console](https://console.aws.amazon.com/config/).
   - Choose `Get started`.
   - Select the resource types you want to record.
   - Specify the S3 bucket to store the configuration snapshots and AWS Config stream.
   - Set up an IAM role to allow AWS Config to access your AWS resources.
   - Review and confirm your settings.

2. **Enable AWS Config using AWS CLI**:
   ```sh
   aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::YOUR_ACCOUNT_ID:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig
   aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=YOUR_S3_BUCKET_NAME
   aws configservice start-configuration-recorder --configuration-recorder-name default

## Step 2: Define AWS Config Rules

AWS Config rules are predefined, customizable rules that AWS Config uses to evaluate whether your AWS resources comply with your configurations.

Example of enabling a managed rule for ensuring EC2 instances are part of an approved AMI:

```sh
aws configservice put-config-rule --config-rule file://ec2-approved-amis-rule.json
```

## Contents of ec2-approved-amis-rule.json:

```yml
{
  "ConfigRuleName": "approved-amis-by-id",
  "Description": "Checks whether running instances are using specified AMIs. Optionally checks root volumes and any attached volumes.",
  "Scope": {
    "ComplianceResourceTypes": [
      "AWS::EC2::Instance"
    ]
  },
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "APPROVED_AMIS_BY_ID"
  },
  "InputParameters": "{\"amiIds\":\"ami-12345678,ami-23456789\"}",
  "MaximumExecutionFrequency": "Six_Hours"
}
```

## Step 3: Use AWS Systems Manager for Patch Management and Automation

AWS Systems Manager provides a unified user interface to view operational data from multiple AWS services and allows you to automate operational tasks across AWS resources.

## Example of setting up Patch Manager to scan and install patches:

```sh
aws ssm create-patch-baseline --name "MyPatchBaseline" --operating-system "AmazonLinux2" --patch-groups "MyPatchGroup"
aws ssm register-patch-baseline-for-patch-group --baseline-id "pb-0123456789abcdef0" --patch-group "MyPatchGroup"
aws ssm create-association --name "AWS-RunPatchBaseline" --targets "Key=tag:Patch Group,Values=MyPatchGroup" --schedule-expression "cron(0 0 * * ? *)"
```