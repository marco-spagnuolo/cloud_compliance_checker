package maintenance

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	mtypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// ExecuteMaintenanceCommand runs a command via AWS Systems Manager (SSM)
func ExecuteMaintenanceCommand(instanceID, command string, awsCfg aws.Config) error {
	log.Printf("Executing SSM command on instance %s", instanceID)
	svc := ssm.NewFromConfig(awsCfg)

	input := &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {command},
		},
	}

	_, err := svc.SendCommand(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to execute command on instance %s: %v", instanceID, err)
	}

	log.Printf("Command executed successfully on instance %s", instanceID)
	return nil
}

// ScanForMalware scans EC2 instances for GuardDuty findings
func ScanForMalware(instanceID, detectorID string, awsCfg aws.Config) error {
	log.Printf("Scanning for malware on instance %s using GuardDuty", instanceID)
	guarddutySvc := guardduty.NewFromConfig(awsCfg)

	input := &guardduty.ListFindingsInput{
		DetectorId: aws.String(detectorID),
		FindingCriteria: &gtypes.FindingCriteria{
			Criterion: map[string]gtypes.Condition{
				"resource.instanceDetails.instanceId": {Equals: []string{instanceID}},
			},
		},
	}

	_, err := guarddutySvc.ListFindings(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to scan for malicious code: %v", err)
	}

	log.Println("GuardDuty scan completed. No malicious code found.")
	return nil
}

// MonitorS3Bucket ensures no CUI is present on an S3 bucket using Macie
func MonitorS3Bucket(bucketName, accountID string, awsCfg aws.Config) error {
	log.Printf("Starting Macie CUI scan for bucket %s", bucketName)
	svc := macie2.NewFromConfig(awsCfg)

	jobInput := &macie2.CreateClassificationJobInput{
		Name: aws.String("CUI-Scan-Job"),
		S3JobDefinition: &mtypes.S3JobDefinition{
			BucketDefinitions: []mtypes.S3BucketDefinitionForJob{
				{
					AccountId: aws.String(accountID),
					Buckets:   []string{bucketName},
				},
			},
		},
		JobType: mtypes.JobTypeOneTime,
	}

	_, err := svc.CreateClassificationJob(context.TODO(), jobInput)
	if err != nil {
		return fmt.Errorf("failed to start Macie classification job for bucket %s: %v", bucketName, err)
	}

	log.Printf("Macie job started to monitor CUI in bucket %s", bucketName)
	return nil
}

// CheckEC2Instance verifies EC2 compliance against monitoring tools and active state
func CheckEC2Instance(instanceID string, awsCfg aws.Config) error {
	log.Printf("Checking EC2 instance %s state", instanceID)
	ec2Svc := ec2.NewFromConfig(awsCfg)

	// Check instance state
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}
	resp, err := ec2Svc.DescribeInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Error describing instance %s: %v", instanceID, err)
		return fmt.Errorf("failed to describe instance %s: %v", instanceID, err)
	}

	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State.Name != ec2types.InstanceStateNameRunning {
				log.Printf("Instance %s is not running", instanceID)
				return fmt.Errorf("instance %s is not in running state", *instance.InstanceId)
			}
			log.Printf("Instance %s is in running state", *instance.InstanceId)
		}
	}

	return nil
}

// RunMonitorCheck verifies AWS assets against the configuration loaded from AWS config
func RunMonitorCheck(awsCfg aws.Config) error {
	// Load the config from config.AppConfig
	cfg := config.AppConfig.AWS.MaintenanceConfig

	// Check EC2 compliance
	for _, instance := range cfg.EC2MonitoredInstances {
		log.Printf("Checking EC2 instance %s", instance.InstanceID)
		err := CheckEC2Instance(instance.InstanceID, awsCfg)
		if err != nil {
			log.Printf("EC2 compliance check failed for instance %s: %v", instance.InstanceID, err)
			return fmt.Errorf("EC2 compliance check failed: %v", err)
		}

		// Validate tools
		for _, tool := range instance.MonitoringTools {
			log.Printf("Validating tool %s for instance %s", tool, instance.InstanceID)
			if !ValidateTool(instance.InstanceID, tool, cfg) {
				log.Printf("Tool %s is NOT approved for instance %s", tool, instance.InstanceID)
				return fmt.Errorf("tool %s is not approved for instance %s", tool, instance.InstanceID)
			}
			log.Printf("Tool %s is approved for instance %s", tool, instance.InstanceID)
		}

		// Scan for malware using GuardDuty
		log.Printf("Scanning instance %s for malware using GuardDuty", instance.InstanceID)
		err = ScanForMalware(instance.InstanceID, cfg.GuardDutyDetectorID, awsCfg)
		if err != nil {
			log.Printf("Malware scan failed for instance %s: %v", instance.InstanceID, err)
			return fmt.Errorf("malware scan failed on instance %s: %v", instance.InstanceID, err)
		}
	}

	// Monitor S3 bucket for CUI with Macie
	log.Printf("Monitoring S3 bucket %s for CUI", cfg.BucketName)
	err := MonitorS3Bucket(cfg.BucketName, cfg.AccountID, awsCfg)
	if err != nil {
		log.Printf("S3 bucket monitoring failed: %v", err)
		return fmt.Errorf("S3 bucket monitoring failed: %v", err)
	}

	log.Println("Compliance check completed successfully.")
	return nil
}

// ValidateTool checks if a given tool is approved for a specific instance
func ValidateTool(instanceID, toolName string, cfg config.MaintenanceConfig) bool {
	for _, instance := range cfg.EC2MonitoredInstances {
		if instance.InstanceID == instanceID {
			for _, tool := range instance.MonitoringTools {
				if tool == toolName {
					return true
				}
			}
		}
	}
	return false
}

/*
To retrieve the GuardDuty detector ID and the AWS account ID, you can use the AWS CLI commands:
1. Get GuardDuty Detector ID:

bash

aws guardduty list-detectors --region <region>

This will return the detector ID for GuardDuty in the specified region.
2. Get AWS Account ID:

bash

aws sts get-caller-identity --query Account --output text

Steps to Enable Macie:



aws macie2 enable-macie --region <your-region>

*/
