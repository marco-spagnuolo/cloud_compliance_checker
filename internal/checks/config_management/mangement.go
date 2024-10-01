package config_management

import (
	"cloud_compliance_checker/config"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// SaveBaselineConfig saves the current baseline configuration to a file
func SaveBaselineConfig(cfg *config.Config, filename string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}

	fmt.Println("Baseline configuration saved successfully.")
	return nil
}

// GetCurrentAWSBaseline retrieves the current AWS resource baseline using the config structure
func GetCurrentAWSBaseline(awsCfg aws.Config) (*config.AWSConfig, error) {
	awsConfig := config.AWSConfig{}

	// Get EC2 instance IDs
	ec2Client := ec2.NewFromConfig(awsCfg)
	ec2Result, err := ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving EC2 instances: %v", err)
	}

	var securityGroups []config.SecurityGroup
	for _, reservation := range ec2Result.Reservations {
		for _, instance := range reservation.Instances {
			securityGroup := config.SecurityGroup{
				Name: *instance.InstanceId,
				// Add appropriate mappings for allowed ingress/egress ports if needed
			}
			securityGroups = append(securityGroups, securityGroup)
		}
	}
	awsConfig.SecurityGroups = securityGroups

	// Get S3 bucket names
	s3Client := s3.NewFromConfig(awsCfg)
	s3Result, err := s3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving S3 buckets: %v", err)
	}

	var s3Buckets []config.S3Bucket
	for _, bucket := range s3Result.Buckets {
		s3Buckets = append(s3Buckets, config.S3Bucket{Name: *bucket.Name, Encryption: "default"}) // Placeholder for encryption
	}
	awsConfig.S3Buckets = s3Buckets

	// Get IAM role names
	iamClient := iam.NewFromConfig(awsCfg)
	iamResult, err := iamClient.ListRoles(context.TODO(), &iam.ListRolesInput{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving IAM roles: %v", err)
	}

	var criticalRoles []config.CriticalRole
	for _, role := range iamResult.Roles {
		criticalRole := config.CriticalRole{
			RoleName: *role.RoleName,
			// Add sensitive functions or other attributes as necessary
		}
		criticalRoles = append(criticalRoles, criticalRole)
	}
	awsConfig.CriticalRole = criticalRoles

	return &awsConfig, nil
}

// CompareBaseline compares the current AWS baseline configuration with the stored YAML baseline configuration
func CompareBaseline(current *config.AWSConfig, stored *config.AWSConfig) bool {
	// Compare S3 Buckets
	if len(current.S3Buckets) != len(stored.S3Buckets) {
		fmt.Println("S3 bucket count has changed!")
		return false
	}

	for i, bucket := range current.S3Buckets {
		if bucket.Name != stored.S3Buckets[i].Name {
			fmt.Printf("S3 bucket %s has changed.\n", bucket.Name)
			return false
		}
	}

	// Compare Security Groups
	if len(current.SecurityGroups) != len(stored.SecurityGroups) {
		fmt.Println("Security group count has changed!")
		return false
	}

	for i, group := range current.SecurityGroups {
		if group.Name != stored.SecurityGroups[i].Name {
			fmt.Printf("Security group %s has changed.\n", group.Name)
			return false
		}
	}

	// Compare IAM Roles
	if len(current.CriticalRole) != len(stored.CriticalRole) {
		fmt.Println("IAM role count has changed!")
		return false
	}

	for i, role := range current.CriticalRole {
		if role.RoleName != stored.CriticalRole[i].RoleName {
			fmt.Printf("IAM role %s has changed.\n", role.RoleName)
			return false
		}
	}

	// Additional comparisons can be added here as needed

	return true
}

// RunAWSBaselineCheck performs the baseline check and updates the configuration if necessary
func RunAWSBaselineCheck(awsCfg aws.Config, storedBaseline *config.AWSConfig) error {
	fmt.Println("Starting AWS asset baseline configuration check...")

	// Retrieve current AWS baseline
	currentBaseline, err := GetCurrentAWSBaseline(awsCfg)
	if err != nil {
		return fmt.Errorf("error retrieving current AWS asset baseline: %v", err)
	}

	// Compare current baseline with stored baseline
	if !CompareBaseline(currentBaseline, storedBaseline) {
		fmt.Println("AWS asset configuration has changed, updating baseline.")
		// Update the stored baseline
		storedBaseline = currentBaseline
		fmt.Println("Baseline updated.")
	} else {
		fmt.Println("AWS asset configuration has not changed.")
	}

	fmt.Println("AWS asset baseline configuration check completed successfully.")
	return nil
}
