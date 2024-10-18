package integrity

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

// CheckSystemMonitoring detects system monitoring for attacks, unauthorized connections, and unusual activities.
// This check includes monitoring through GuardDuty, VPC Flow Logs, and CloudWatch Logs.
// 03.14.06
func CheckSystemMonitoring(cfg aws.Config) error {
	ctx := context.TODO()

	// Step 1: Check if GuardDuty is enabled and actively monitoring
	log.Println("Checking GuardDuty monitoring...")
	if err := checkGuardDutyMonitoring(ctx, cfg); err != nil {
		return fmt.Errorf("GuardDuty monitoring check failed: %v", err)
	}
	log.Println("GuardDuty is monitoring for potential attacks.")

	// Step 2: Check if VPC Flow Logs are enabled on all VPCs
	log.Println("Checking VPC Flow Logs for network traffic monitoring...")
	if err := checkVPCFlowLogs(ctx, cfg); err != nil {
		return fmt.Errorf("VPC Flow Logs check failed: %v", err)
	}
	log.Println("VPC Flow Logs are enabled on all VPCs.")

	// Step 3: Check CloudWatch Logs for system event monitoring
	log.Println("Checking CloudWatch Logs for system event monitoring...")
	if err := checkCloudWatchLogs(ctx, cfg); err != nil {
		return fmt.Errorf("CloudWatch Logs check failed: %v", err)
	}
	log.Println("CloudWatch Logs are actively monitoring system activities.")

	return nil
}

// checkGuardDutyMonitoring checks if GuardDuty is enabled and actively monitoring for threats.
func checkGuardDutyMonitoring(ctx context.Context, cfg aws.Config) error {
	gdClient := guardduty.NewFromConfig(cfg)

	// Get GuardDuty detectors (should return 1 if GuardDuty is enabled)
	detectors, err := gdClient.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return fmt.Errorf("failed to list GuardDuty detectors: %v", err)
	}

	if len(detectors.DetectorIds) == 0 {
		return fmt.Errorf("GuardDuty is not enabled")
	}

	// Optional: Check for findings
	findings, err := gdClient.ListFindings(ctx, &guardduty.ListFindingsInput{
		DetectorId: aws.String(detectors.DetectorIds[0]),
	})
	if err != nil {
		return fmt.Errorf("failed to list GuardDuty findings: %v", err)
	}

	log.Printf("GuardDuty is active. Findings count: %d\n", len(findings.FindingIds))
	return nil
}

// checkVPCFlowLogs checks if VPC Flow Logs are enabled for all VPCs
func checkVPCFlowLogs(ctx context.Context, cfg aws.Config) error {
	ec2Client := ec2.NewFromConfig(cfg)

	// Describe VPCs
	vpcs, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe VPCs: %v", err)
	}

	for _, vpc := range vpcs.Vpcs {
		// Check VPC Flow Logs for each VPC
		flowLogs, err := ec2Client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
			Filter: []types.Filter{
				{
					Name:   aws.String("resource-id"),
					Values: []string{*vpc.VpcId},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to describe flow logs for VPC %s: %v", *vpc.VpcId, err)
		}

		if len(flowLogs.FlowLogs) == 0 {
			return fmt.Errorf("VPC %s does not have Flow Logs enabled", *vpc.VpcId)
		}

		log.Printf("VPC %s has Flow Logs enabled.\n", *vpc.VpcId)
	}

	return nil
}

// checkCloudWatchLogs checks if there are CloudWatch Log groups for monitoring system events
func checkCloudWatchLogs(ctx context.Context, cfg aws.Config) error {
	cwClient := cloudwatchlogs.NewFromConfig(cfg)

	// List all CloudWatch Log Groups
	logGroups, err := cwClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe CloudWatch Log Groups: %v", err)
	}

	if len(logGroups.LogGroups) == 0 {
		return fmt.Errorf("no CloudWatch Log Groups found for system monitoring")
	}

	log.Printf("CloudWatch is monitoring %d log groups.\n", len(logGroups.LogGroups))
	return nil
}
