# AWS Security Configuration - NIST SP 800-171 v3 Compliance Checker

## Overview

This repository contains an AWS security configuration file designed to meet the compliance requirements outlined in the NIST SP 800-171 Rev. 3.0. The file configures user roles, security policies, access controls, and monitoring for AWS services. It ensures that critical security measures such as encryption, multi-factor authentication (MFA), and access management are properly configured to maintain the confidentiality, integrity, and availability of Controlled Unclassified Information (CUI).

## How to Run the Compliance Checker

To run the compliance checker and generate the compliance report, follow these steps:

1. **Prepare Credentials File**: 
   Create a YAML file (name it as you prefer, e.g., `my_config.yaml`) with the following structure:
   ```yaml
   aws:
     access_key: YOUR_AWS_ACCESS_KEY
     secret_key: YOUR_AWS_SECRET_KEY
     region: YOUR_REGION
   ```

   You can use the following example configuration file for reference: [config.yaml](https://github.com/marco-spagnuolo/cloud_compliance_checker/blob/main/config/config.yaml).

2. **Run the Go Script**:
   Execute the following command to run the compliance checker:
   ```bash
   go run main.go --config your_config_file.yaml
   ```

3. **Generate Compliance Report**:
   After the script completes execution, a PDF file named `compliance_report.pdf` will be generated in the root directory of the project. This report will contain the results of the compliance checks, detailing any issues or non-compliance found in your AWS environment.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Configuration Structure](#configuration-structure)
    - [AWS Credentials](#1-aws-credentials)
    - [User and Policies](#2-user-and-policies)
    - [Accepted Policies](#3-accepted-policies)
    - [Security Groups](#4-security-groups)
    - [S3 Buckets Encryption](#5-s3-buckets-encryption)
    - [Separation of Duties](#6-separation-of-duties)
    - [Login Policy](#7-login-policy)
    - [Remote Access Control](#8-remote-access-control)
    - [Risk Assessment](#9-risk-assessment)
    - [System Maintenance](#10-system-maintenance)
    - [Password Policy](#11-password-policy)
    - [Data Integrity](#12-data-integrity)
3. [Best Practices](#best-practices)
4. [Contact](#contact)

## Requirements

- **AWS CLI**: Ensure that the AWS CLI is installed and configured on your machine.
- **AWS Account**: Valid AWS access and secret keys for managing resources.
- **YAML Validator**: To ensure that the configuration is syntactically correct.
- **Go Programming Language**: Ensure Go is installed on your machine.

## Configuration Structure

### 1. AWS Credentials

You need to provide your AWS access and secret keys along with the region where your infrastructure is deployed.

```yaml
aws:
  access_key: YOUR_AWS_ACCESS_KEY
  secret_key: YOUR_AWS_SECRET_KEY
  region: us-east-1
```

### 2. User and Policies

This section defines the users, their assigned policies, and their security functions. Each user can have specific access permissions, MFA requirements, and re-authentication conditions.

```yaml
users:
  - name: AdminUser
    policies: [AdministratorAccess, SNSPublishPolicy]
    mfa_required: true
    is_privileged: true
```

### 3. Accepted Policies

Lists all accepted IAM policies that can be applied to the users. Ensure that only these approved policies are used to manage the security of your AWS environment.

```yaml
accepted_policies:
  - AdministratorAccess
  - PowerUserAccess
  - ReadOnlyAccess
```

### 4. Security Groups

Defines the security groups and the allowed ingress (incoming) and egress (outgoing) ports. Ensure that only required ports are open to reduce the attack surface.

```yaml
security_groups:
  - name: default
    allowed_ingress_ports: []
    allowed_egress_ports: []
```

### 5. S3 Buckets Encryption

Defines S3 buckets and their respective encryption methods. Always ensure that sensitive data is encrypted at rest.

```yaml
s3_buckets:
  - name: my-cui-bucket
    encryption: AES256
```

### 6. Separation of Duties

Configures roles and separates sensitive functions to enforce the principle of least privilege and avoid conflicts of interest.

```yaml
critical_role:
  - role_name: AdminRole
    sensitive_functions: [ManageIAM, ManageEC2]
```

### 7. Login Policy

Sets the maximum number of unsuccessful login attempts, the lockout duration, and the action taken on lockout.

```yaml
login_policy:
  user: "marco"
  max_unsuccessful_attempts: 5
  lockout_duration_minutes: 15
```

### 8. Remote Access Control

Defines authorized software and instances for remote access, ensuring only specific EC2 instances and applications can be accessed remotely.

```yaml
ec2_instances:
  - instance_id: i-03feff3c4b19de9d6
    authorized_software: [nginx, docker, sshd]
```

### 9. Risk Assessment

Configures the frequency of risk assessments and vulnerability scanning to identify potential risks in your AWS environment.

```yaml
risk_assessment:
  frequency: "monthly"
  vulnerability_scanning:
    frequency: "weekly"
```

### 10. System Maintenance

Defines the approved tools and EC2 instances for system maintenance. It also lists the users authorized for non-local maintenance.

```yaml
maintainance:
  approved_maintenance_tools: [aws-cli, aws-shell]
  authorized_users:
    user_names: ["maintainer1", "maintainer2"]
```

### 11. Password Policy

Enforces a strong password policy to mitigate the risk of unauthorized access to AWS resources.

```yaml
password_policy:
  min_length: 12
  require_numbers: true
  require_symbols: true
  require_uppercase: true
  require_lowercase: true
```

### 12. Data Integrity

Monitors the integrity of critical data using AWS Lambda functions for security alerts and checks for any unauthorized changes.

```yaml
integrity:
  bucket_names: [my-cui-bucket]
  lambda_name: "arn:aws:lambda:us-east-1:682033472444:function:SecurityAlertsFunction"
```

## Best Practices

- **Regular Audits**: Continuously monitor and audit the AWS environment to ensure ongoing compliance with NIST SP 800-171.
- **MFA**: Enforce multi-factor authentication for all privileged users to enhance security.
- **Encryption**: Ensure that all sensitive data in S3 buckets is encrypted with strong encryption methods like AES256 or AWS KMS.
- **Least Privilege**: Grant only the permissions necessary for users and services to perform their required functions.
- **Automate Monitoring**: Use AWS Config, CloudTrail, and Lambda to automate compliance monitoring and incident response.

