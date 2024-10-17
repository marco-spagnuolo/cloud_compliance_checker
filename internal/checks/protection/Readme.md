# 03.13.01 

This document provides a set of AWS CLI commands that can be used to verify and configure various AWS services, such as NAT Gateways, Internet Gateways, VPN Connections, CloudWatch Log Groups, and Web ACLs. These commands are useful for ensuring that your AWS environment is properly configured for network security and compliance purposes.

## AWS CLI Commands for Verification

### 1. NAT Gateways

To list all the NAT Gateways in your AWS environment, use the following command:

```bash\
aws ec2 describe-nat-gateways --query "NatGateways[*].NatGatewayId"
```

**Explanation**: This command retrieves and displays the IDs of all NAT Gateways configured in your AWS account. NAT Gateways are used to allow private subnets to access the internet without exposing them directly.

### 2. Internet Gateways

To list all the Internet Gateways, run:

```bash\
aws ec2 describe-internet-gateways --query "InternetGateways[*].InternetGatewayId"
```

**Explanation**: This command retrieves the IDs of all Internet Gateways in your AWS environment. Internet Gateways enable communication between your VPC and the internet.

### 3. VPN Connections

To check the VPN Connections, use:

```bash\
aws ec2 describe-vpn-connections --query "VpnConnections[*].VpnConnectionId"
```

**Explanation**: This command lists all the VPN Connections available in your account, which are used to securely connect your on-premises network to your AWS VPC.

### 4. CloudWatch Log Groups

To view the existing CloudWatch Log Groups, use:

```bash\
aws logs describe-log-groups --query "logGroups[*].logGroupName"
```

**Explanation**: This command retrieves the names of all CloudWatch Log Groups. CloudWatch Log Groups help you collect and monitor logs from different AWS resources.

### 5. AWS WAF Web ACLs - Regional

To list all Regional Web ACLs (e.g., for Application Load Balancers or API Gateways):

```bash\
aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[*].Name" --region us-east-1
```

**Explanation**: This command checks for the presence of Web ACLs configured under the `REGIONAL` scope. Regional Web ACLs protect resources like ALBs and API Gateways from security threats.

### 6. AWS WAF Web ACLs - CloudFront

To list Web ACLs configured for CloudFront (global):

```bash\
aws wafv2 list-web-acls --scope CLOUDFRONT --query "WebACLs[*].Name"
```

**Explanation**: This command retrieves Web ACLs configured under the `CLOUDFRONT` scope. Web ACLs for CloudFront help protect your CloudFront distributions globally from various web threats.

## AWS CLI Commands for Configuration

### 1. Create a Regional Web ACL

To create a Web ACL for regional resources (e.g., ALB or API Gateway) in `us-east-1`:

```bash\
aws wafv2 create-web-acl \\
    --name "MyRegionalWebACL" \\
    --scope REGIONAL \\
    --default-action Block={} \\
    --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="MyWebACLMetric" \\
    --region us-east-1\
```

**Explanation**: This command creates a new Web ACL named `MyRegionalWebACL` for regional use. It sets the default action to `Block`, enabling sample requests and CloudWatch metrics for monitoring purposes. Make sure to replace `"MyRegionalWebACL"` with your desired Web ACL name.

### 2. Create a CloudFront Web ACL

To create a Web ACL for use with CloudFront (global):

```bash\
aws wafv2 create-web-acl \\
    --name "MyCloudFrontWebACL" \\
    --scope CLOUDFRONT \\
    --default-action Block={} \\
    --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="MyWebACLMetric"\
```

**Explanation**: This command creates a new Web ACL named `MyCloudFrontWebACL` for use with CloudFront distributions. The Web ACL will apply globally and will use `Block` as the default action, with metrics enabled for monitoring.

## Notes

- Ensure that your AWS CLI is properly configured with the necessary permissions to run these commands.\
- Replace placeholder values like `"MyRegionalWebACL"` and `"MyWebACLMetric"` with your own preferred names where necessary.\
- The region flag (`--region`) is required for regional resources. CloudFront does not require a region as it operates globally.

By using these commands, you can manage and verify your AWS network security configurations effectively.

---

