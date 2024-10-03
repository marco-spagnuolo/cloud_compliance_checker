package config_management

import (
	"cloud_compliance_checker/config"
	"cloud_compliance_checker/discovery"
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// HighRiskTravelInfo stores information about AWS assets assigned to individuals traveling to high-risk locations.
type HighRiskTravelInfo struct {
	UserID           string
	AWSAssetID       string
	AWSAssetType     string
	HighRiskLocation string
	AssignedDate     time.Time
	ReturnDate       time.Time
}

// Global list to store high-risk travel information for AWS assets
var highRiskTravelLog []HighRiskTravelInfo

// Helper function to get security group ID by name, and create it if it doesn't exist
func getOrCreateSecurityGroup(ec2Client *ec2.Client, groupName, vpcID string) (string, error) {
	// First, try to fetch the security group by name
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []string{groupName},
			},
		},
	}

	result, err := ec2Client.DescribeSecurityGroups(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe security groups: %v", err)
	}

	if len(result.SecurityGroups) > 0 {
		return *result.SecurityGroups[0].GroupId, nil
	}

	// If the security group is not found, create it
	fmt.Printf("Security group '%s' not found, creating it...\n", groupName)

	createInput := &ec2.CreateSecurityGroupInput{
		Description: aws.String("Security group for high-risk travel assets"),
		GroupName:   aws.String(groupName),
		VpcId:       aws.String(vpcID),
	}

	createResult, err := ec2Client.CreateSecurityGroup(context.TODO(), createInput)
	if err != nil {
		return "", fmt.Errorf("failed to create security group '%s': %v", groupName, err)
	}

	// Apply ingress/egress rules (allowing SSH and HTTP as an example)
	_, err = ec2Client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: createResult.GroupId,
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"), // Allow SSH from anywhere
					},
				},
			},
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"), // Allow HTTP from anywhere
					},
				},
			},
		},
	})

	if err != nil {
		return "", fmt.Errorf("failed to set security group rules for '%s': %v", groupName, err)
	}

	fmt.Printf("Security group '%s' created with ID %s\n", groupName, *createResult.GroupId)
	return *createResult.GroupId, nil
}

// Helper function to get VPC ID for an instance
func getVpcIDForInstance(ec2Client *ec2.Client, instanceID string) (string, error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe instance %s: %v", instanceID, err)
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("instance %s not found", instanceID)
	}

	return *result.Reservations[0].Instances[0].VpcId, nil
}

// Assign AWS asset to an individual traveling to a high-risk area
func AssignAWSAssetForHighRiskTravel(cfg aws.Config, userID, assetID, assetType, location string) {
	user := findHighRiskTravelUser(userID)
	if user == nil {
		fmt.Printf("User with ID %s not found in the configuration.\n", userID)
		return
	}

	highRiskEntry := HighRiskTravelInfo{
		UserID:           userID,
		AWSAssetID:       assetID,
		AWSAssetType:     assetType,
		HighRiskLocation: location,
		AssignedDate:     time.Now(),
	}

	highRiskTravelLog = append(highRiskTravelLog, highRiskEntry)

	// Apply pre-travel configurations to the AWS asset
	applyAWSPreTravelConfigurations(assetID, assetType, cfg)

	fmt.Printf("AWS Asset %s (%s) assigned to user %s (%s) for travel to high-risk location: %s\n", assetID, assetType, user.Name, user.Role, location)
}

// findHighRiskTravelUser finds a user by ID from the high-risk travel configuration
func findHighRiskTravelUser(userID string) *config.HighRiskTravelUser {
	for _, user := range config.AppConfig.AWS.HighRiskTravelConfig.Users {
		if user.UserID == userID {
			return &user
		}
	}
	return nil
}

// Apply pre-travel configurations to AWS assets (EC2, S3) before travel to high-risk areas
func applyAWSPreTravelConfigurations(assetID, assetType string, cfg aws.Config) {
	preTravelConfig := config.AppConfig.AWS.HighRiskTravelConfig.PreTravelConfig
	switch assetType {
	case "EC2 Instance":
		applyEC2PreTravelConfig(cfg, assetID, preTravelConfig.EC2SecurityGroup)
	case "S3 Bucket":
		applyS3PreTravelConfig(cfg, assetID, preTravelConfig.S3Encryption)
	}
}

// Apply EC2-specific pre-travel configurations (restrictive security groups)
func applyEC2PreTravelConfig(cfg aws.Config, instanceID, securityGroupName string) {

	ec2Client := ec2.NewFromConfig(cfg)

	// Fetch VPC ID for the instance
	vpcID, err := getVpcIDForInstance(ec2Client, instanceID)
	if err != nil {
		fmt.Printf("Failed to fetch VPC ID for instance %s: %v\n", instanceID, err)
		return
	}

	// Fetch or create security group
	securityGroupID, err := getOrCreateSecurityGroup(ec2Client, securityGroupName, vpcID)
	if err != nil {
		fmt.Printf("Failed to fetch or create security group ID for group %s: %v\n", securityGroupName, err)
		return
	}

	// Update security group for EC2 instance
	input := &ec2.ModifyInstanceAttributeInput{
		InstanceId: &instanceID,
		Groups:     []string{securityGroupID},
	}

	_, err = ec2Client.ModifyInstanceAttribute(context.TODO(), input)
	if err != nil {
		fmt.Printf("Failed to apply security group to EC2 instance %s: %v\n", instanceID, err)
	} else {
		fmt.Printf("Applied security group %s (ID: %s) to EC2 instance %s\n", securityGroupName, securityGroupID, instanceID)
	}
}

// Apply S3-specific pre-travel configurations (ensure encryption)
func applyS3PreTravelConfig(cfg aws.Config, bucketName, encryptionType string) {

	s3Client := s3.NewFromConfig(cfg)

	// Enable server-side encryption for the S3 bucket
	input := &s3.PutBucketEncryptionInput{
		Bucket: &bucketName,
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
						SSEAlgorithm: s3types.ServerSideEncryptionAes256,
					},
				},
			},
		},
	}

	_, err := s3Client.PutBucketEncryption(context.TODO(), input)
	if err != nil {
		fmt.Printf("Failed to enable encryption for S3 bucket %s: %v\n", bucketName, err)
	} else {
		fmt.Printf("Enabled encryption (%s) for S3 bucket %s\n", encryptionType, bucketName)
	}
}

// Perform security checks and actions when an individual returns from a high-risk location
func PerformAWSPostTravelChecks(cfg aws.Config, userID, assetID, assetType string) {
	postTravelChecks := config.AppConfig.AWS.HighRiskTravelConfig.PostTravelChecks

	fmt.Printf("Performing post-travel security checks for AWS asset %s (%s) assigned to user %s...\n", assetID, assetType, userID)

	switch assetType {
	case "EC2 Instance":
		if postTravelChecks.VerifySecGroups {
			checkEC2PostTravel(cfg, assetID)
		}
	case "S3 Bucket":
		if postTravelChecks.VerifyEncryption {
			checkS3PostTravel(cfg, assetID)
		}
	}

	fmt.Printf("Post-travel security checks completed for AWS asset %s.\n", assetID)
}

// Check EC2 CloudTrail logs and restore default security settings
func checkEC2PostTravel(cfg aws.Config, instanceID string) {

	ec2Client := ec2.NewFromConfig(cfg)

	// Simulate checking CloudTrail logs
	fmt.Printf("Checking CloudTrail logs for EC2 instance %s...\n", instanceID)

	// Fetch the default security group by name (you should specify the correct name)
	defaultSecurityGroupName := "default"
	securityGroupID, err := getOrCreateSecurityGroup(ec2Client, defaultSecurityGroupName, "your-vpc-id") // Replace with actual VPC ID
	if err != nil {
		fmt.Printf("Failed to fetch default security group ID for group %s: %v\n", defaultSecurityGroupName, err)
		return
	}

	// Restore default security group
	input := &ec2.ModifyInstanceAttributeInput{
		InstanceId: &instanceID,
		Groups:     []string{securityGroupID},
	}

	_, err = ec2Client.ModifyInstanceAttribute(context.TODO(), input)
	if err != nil {
		fmt.Printf("Failed to restore security group for EC2 instance %s: %v\n", instanceID, err)
	} else {
		fmt.Printf("Restored default security group (ID: %s) for EC2 instance %s\n", securityGroupID, instanceID)
	}
}

// Check S3 CloudTrail logs and verify encryption
func checkS3PostTravel(cfg aws.Config, bucketName string) {

	s3Client := s3.NewFromConfig(cfg)

	// Simulate checking CloudTrail logs
	fmt.Printf("Checking CloudTrail logs for S3 bucket %s...\n", bucketName) // TODO Implement CloudTrail log check

	// Verify that encryption is still enabled
	input := &s3.GetBucketEncryptionInput{
		Bucket: &bucketName,
	}

	output, err := s3Client.GetBucketEncryption(context.TODO(), input)
	if err != nil {
		fmt.Printf("Failed to verify encryption for S3 bucket %s: %v\n", bucketName, err)
	} else if len(output.ServerSideEncryptionConfiguration.Rules) > 0 {
		fmt.Printf("Encryption is enabled for S3 bucket %s\n", bucketName)
	} else {
		fmt.Printf("Encryption is NOT enabled for S3 bucket %s!\n", bucketName)
	}
}

// Example compliance check function for high-risk travel
func CheckHighRiskTravelCompliance(awsCfg aws.Config) error {
	// Discover assets (EC2, S3) assigned for high-risk travel
	assets := discovery.DiscoverAssets(awsCfg)

	// Assign the user based on the high-risk travel configuration
	for i, asset := range assets {
		userID := config.AppConfig.AWS.HighRiskTravelConfig.Users[i%len(config.AppConfig.AWS.HighRiskTravelConfig.Users)].UserID
		AssignAWSAssetForHighRiskTravel(awsCfg, userID, asset.Name, asset.Type, "high-risk-location")

		// Perform post-travel checks
		PerformAWSPostTravelChecks(awsCfg, userID, asset.Name, asset.Type)
	}

	return nil
}
