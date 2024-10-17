package protection

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
)

/*
aws ec2 describe-nat-gateways --query "NatGateways[*].NatGatewayId"\n
aws ec2 describe-internet-gateways --query "InternetGateways[*].InternetGatewayId"\n
aws ec2 describe-vpn-connections --query "VpnConnections[*].VpnConnectionId"\n
aws logs describe-log-groups --query "logGroups[*].logGroupName"\n
aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[*].Name"\n
aws wafv2 list-web-acls --scope CLOUDFRONT --query "WebACLs[*].Name"\n
aws wafv2 create-web-acl \\n    --name "MyRegionalWebACL" \\n    --scope REGIONAL \\n    --default-action Block={} \\n    --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="MyWebACLMetric" \\n    --region us-east-1\n
aws wafv2 create-web-acl \\n    --name "MyCloudFrontWebACL" \\n    --scope CLOUDFRONT \\n    --default-action Block={} \\n    --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName="MyWebACLMetric"\n
*/

// VerifyCompliance checks that all the necessary AWS components are in place and functioning
// 3.13.01
func VerifyComponents(awsCfg aws.Config) error {
	// Step 1: Check if there is at least one VPC
	if err := verifyVPC(context.TODO(), awsCfg); err != nil {
		return fmt.Errorf("VPC verification failed: %v", err)
	}

	// Step 2: Check Managed Interfaces (e.g., NAT Gateway, Internet Gateway)
	if err := checkManagedInterfaces(context.TODO(), awsCfg, config.AppConfig.AWS.Protection.ManagedServices); err != nil {
		return fmt.Errorf("managed interfaces verification failed: %v", err)
	}

	// Step 3: Check Security Services (AWS WAF, Network Firewall)
	if err := checkSecurityServices(context.TODO(), awsCfg); err != nil {
		return fmt.Errorf("security services verification failed: %v", err)
	}

	// Step 4: Verify Logging and Monitoring (CloudTrail, CloudWatch Logs)
	if err := verifyLogging(context.TODO(), awsCfg, config.AppConfig.AWS.Protection.LogGroupName); err != nil {
		return fmt.Errorf("logging verification failed: %v", err)
	}

	log.Println("All compliance checks passed successfully.")
	return nil
}

// Helper to verify that there is at least one VPC
func verifyVPC(ctx context.Context, cfg aws.Config) error {
	svc := ec2.NewFromConfig(cfg)
	input := &ec2.DescribeVpcsInput{}

	result, err := svc.DescribeVpcs(ctx, input)
	if err != nil || len(result.Vpcs) == 0 {
		return fmt.Errorf("no VPCs found or error occurred: %v", err)
	}

	log.Printf("Found %d VPC(s), at least one VPC is active.\n", len(result.Vpcs))
	return nil
}

// Helper to check Managed Interfaces (e.g., NAT, VPN)
func checkManagedInterfaces(ctx context.Context, cfg aws.Config, services []string) error {
	svc := ec2.NewFromConfig(cfg)

	for _, service := range services {
		switch service {
		case "NAT":
			input := &ec2.DescribeNatGatewaysInput{}
			result, err := svc.DescribeNatGateways(ctx, input)
			if err != nil || len(result.NatGateways) == 0 {
				return fmt.Errorf("no NAT Gateways found or error occurred: %v", err)
			}
			log.Println("NAT Gateway is active.")

		case "IGW":
			input := &ec2.DescribeInternetGatewaysInput{}
			result, err := svc.DescribeInternetGateways(ctx, input)
			if err != nil || len(result.InternetGateways) == 0 {
				return fmt.Errorf("no Internet Gateways found or error occurred: %v", err)
			}
			log.Println("Internet Gateway is active.")

		case "VPN":
			input := &ec2.DescribeVpnConnectionsInput{}
			result, err := svc.DescribeVpnConnections(ctx, input)
			if err != nil || len(result.VpnConnections) == 0 {
				return fmt.Errorf("no VPN Connections found or error occurred: %v", err)
			}
			log.Println("VPN Connection is active.")
		}
	}

	return nil
}

// Helper to check Security Services (AWS WAF)
func checkSecurityServices(ctx context.Context, cfg aws.Config) error {
	svc := wafv2.NewFromConfig(cfg)

	// Check for Regional Web ACLs
	regionalInput := &wafv2.ListWebACLsInput{
		Scope: "REGIONAL", // For resources like ALB and API Gateway
	}
	regionalResult, err := svc.ListWebACLs(ctx, regionalInput)
	if err != nil {
		return fmt.Errorf("error checking regional WAF Web ACLs: %v", err)
	}

	// Check for CloudFront Web ACLs (Global)
	cloudfrontInput := &wafv2.ListWebACLsInput{
		Scope: "CLOUDFRONT", // For resources like CloudFront distributions
	}
	cloudfrontResult, err := svc.ListWebACLs(ctx, cloudfrontInput)
	if err != nil {
		return fmt.Errorf("error checking CloudFront WAF Web ACLs: %v", err)
	}

	// Evaluate results for both scopes
	if len(regionalResult.WebACLs) == 0 && len(cloudfrontResult.WebACLs) == 0 {
		return fmt.Errorf("no WAF Web ACLs found in either Regional or CloudFront scope")
	}

	// Log which Web ACLs are active
	if len(regionalResult.WebACLs) > 0 {
		log.Printf("Found %d Regional WAF Web ACL(s).\n", len(regionalResult.WebACLs))
	}
	if len(cloudfrontResult.WebACLs) > 0 {
		log.Printf("Found %d CloudFront WAF Web ACL(s).\n", len(cloudfrontResult.WebACLs))
	}

	return nil
}

// Helper to verify Logging and Monitoring (CloudWatch Logs and CloudTrail)
func verifyLogging(ctx context.Context, cfg aws.Config, logGroupName string) error {
	// Verify CloudWatch Logs
	logsSvc := cloudwatchlogs.NewFromConfig(cfg)
	_, err := logsSvc.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(logGroupName),
	})
	if err != nil {
		return fmt.Errorf("CloudWatch Log Group %s not found: %v", logGroupName, err)
	}
	log.Println("CloudWatch Log Group is active.")

	// Verify CloudTrail
	trailSvc := cloudtrail.NewFromConfig(cfg)
	trailList, err := trailSvc.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil || len(trailList.TrailList) == 0 {
		return fmt.Errorf("CloudTrail is not configured or error occurred: %v", err)
	}

	log.Println("CloudTrail is configured and active.")
	return nil
}

// CheckBoundaryProtection checks if the network boundaries are properly protected
// by examining the security group configurations. Returns an error if open access is found.
func CheckBoundaryProtection(ctx context.Context, cfg aws.Config) error {
	ec2Svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeSecurityGroupsInput{}
	result, err := ec2Svc.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return fmt.Errorf("error describing security groups: %v", err)
	}

	for _, group := range result.SecurityGroups {
		for _, permission := range group.IpPermissions {
			for _, ipRange := range permission.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					return fmt.Errorf("security group %s has open access (0.0.0.0/0)", *group.GroupId)
				}
			}
		}
	}

	// If no open access found, return nil indicating all security groups are properly configured.
	return nil
}
