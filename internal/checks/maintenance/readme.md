# NIST SP 800-171 Compliance Checks Documentation

## 03.07.4 - Monitoring and Control of System Maintenance Tools

### Purpose\
This control focuses on the monitoring and control of system maintenance tools, particularly when dealing with nonlocal maintenance activities. It ensures that systems are not compromised during maintenance sessions by verifying and monitoring the presence of tools, checking for malware, and managing sensitive data.

### Steps for Compliance:

1\. **Retrieve GuardDuty Detector ID & AWS Account ID:**\
    - Use the following AWS CLI commands:\
      ```bash\
      aws guardduty list-detectors --region <region>\
      aws sts get-caller-identity --query Account --output text\
      ```

2\. **Enable AWS Macie:**\
    - Macie helps in monitoring S3 buckets for sensitive information.\
      ```bash\
      aws macie2 enable-macie --region <your-region>\
      ```

### Explanation:\
The steps above ensure that the necessary security measures are in place to monitor tools, scan for malware using GuardDuty, and identify potential threats. Macie helps detect sensitive information, providing extra layers of security during maintenance.

## 03.07.5 - Secure Nonlocal Maintenance Setup

### Purpose\
To set up EC2 instances for secure nonlocal maintenance, ensuring that only authorized, monitored, and controlled maintenance activities occur, complying with NIST SP 800-171.

### Commands:

1\. **Associate IAM Role with EC2 Instances:**\
    ```bash\
    aws ec2 associate-iam-instance-profile --instance-id i-0f4e71312063aa936 --iam-instance-profile Name=ec2_ssm\
    aws ec2 associate-iam-instance-profile --instance-id i-0bd4d11a93aa8d82b --iam-instance-profile Name=ec2_ssm\
    ```

2\. **Authorize Outbound SSM Traffic:**\
    ```bash\
    aws ec2 authorize-security-group-egress --group-id sg-07b2f890b6a328d12 --protocol tcp --port 443 --cidr 0.0.0.0/0\
    ```

3\. **Restart SSM Agent on Each Instance:**\
    ```bash\
    sudo systemctl restart amazon-ssm-agent\
    ```

### Explanation:\
These steps ensure that instances can securely connect via AWS Systems Manager, allowing authorized remote maintenance. The IAM role allows proper permissions, and SSM agents facilitate secure connections.

## 03.07.6 - Authorization of Maintenance Personnel

### Purpose\
To establish a clear process for authorizing maintenance personnel, ensuring that only authorized and appropriately supervised individuals can access and maintain the system.

### Steps for Compliance:

1\. **Tag Users with Maintenance Role:**\
    - Use the following AWS CLI commands to tag users:\
      ```bash\
      aws iam tag-user --user-name maintainer1 --tags Key=Role,Value=maintenance\
      aws iam tag-user --user-name maintainer2 --tags Key=Role,Value=maintenance\
      aws iam tag-user --user-name maintainer3 --tags Key=Role,Value=maintenance\
      ```

2\. **Maintain a List of Authorized Personnel:**\
    - Update your YAML configuration with a list of authorized maintenance users. The system will verify this list against the tags to confirm authorization.

### Explanation:\
By tagging users and verifying their authorization via tags, you can ensure that only approved personnel conduct maintenance. This process also makes it easier to manage temporary permissions and supervise external maintenance staff securely.