package audit

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

func CheckMonitoringTools(awsCfg aws.Config) error {
	log.Println("Starting check for required monitoring tools...")

	if err := isCloudTrailEnabled(awsCfg); err != nil {
		log.Printf("[ERROR] CloudTrail check failed: %v", err)
		return fmt.Errorf("CloudTrail error: %v", err)
	}
	log.Println("[INFO] CloudTrail is properly configured.")

	if err := isAWSConfigEnabled(awsCfg); err != nil {
		log.Printf("[ERROR] AWS Config check failed: %v", err)
		return fmt.Errorf("AWS Config error: %v", err)
	}
	log.Println("[INFO] AWS Config is properly configured.")

	if err := isSecurityHubEnabled(awsCfg); err != nil {
		log.Printf("[ERROR] Security Hub check failed: %v", err)
		return fmt.Errorf("security Hub error: %v", err)
	}
	log.Println("[INFO] Security Hub is properly configured.")

	log.Println("All required monitoring tools are properly configured.")
	return nil
}

func isCloudTrailEnabled(awsCfg aws.Config) error {
	log.Println("[INFO] Checking if CloudTrail is enabled...")
	svc := cloudtrail.NewFromConfig(awsCfg)
	input := &cloudtrail.DescribeTrailsInput{}
	result, err := svc.DescribeTrails(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to describe trails: %v", err)
	}
	if len(result.TrailList) == 0 {
		return fmt.Errorf("no CloudTrail trails found")
	}
	log.Printf("[INFO] Found %d CloudTrail trail(s).", len(result.TrailList))
	return nil
}

func isAWSConfigEnabled(awsCfg aws.Config) error {
	log.Println("[INFO] Checking if AWS Config is enabled and recording...")
	svc := configservice.NewFromConfig(awsCfg)
	input := &configservice.DescribeConfigurationRecorderStatusInput{}
	result, err := svc.DescribeConfigurationRecorderStatus(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to describe configuration recorder status: %v", err)
	}
	if len(result.ConfigurationRecordersStatus) == 0 || !result.ConfigurationRecordersStatus[0].Recording {
		return fmt.Errorf("AWS Config is not enabled or not recording")
	}
	log.Printf("[INFO] AWS Config is enabled and recording status: %t", result.ConfigurationRecordersStatus[0].Recording)
	return nil
}

func isSecurityHubEnabled(awsCfg aws.Config) error {
	log.Println("[INFO] Checking if Security Hub is active...")
	svc := securityhub.NewFromConfig(awsCfg)
	input := &securityhub.DescribeHubInput{}
	_, err := svc.DescribeHub(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("security Hub is not active: %v", err)
	}
	log.Println("[INFO] Security Hub is active.")
	return nil
}
