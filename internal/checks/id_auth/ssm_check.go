package id_auth

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Function to list EC2 instances dynamically
func listEC2Instances(cfg aws.Config) ([]string, error) {
	ec2Client := ec2.NewFromConfig(cfg)
	// Describe all instances
	input := &ec2.DescribeInstancesInput{}
	output, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("unable to describe EC2 instances: %v", err)
	}

	// Extract instance IDs from the response
	var instanceIDs []string
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			instanceIDs = append(instanceIDs, *instance.InstanceId)
		}
	}
	return instanceIDs, nil
}

// Function to check if a specific instance is registered with SSM
func isSSMRegistered(cfg aws.Config, instanceID string) (bool, error) {
	ssmClient := ssm.NewFromConfig(cfg)
	// Call DescribeInstanceInformation to get SSM managed instances
	input := &ssm.DescribeInstanceInformationInput{
		Filters: []types.InstanceInformationStringFilter{
			{
				Key:    aws.String("InstanceIds"),
				Values: []string{instanceID},
			},
		},
	}
	resp, err := ssmClient.DescribeInstanceInformation(context.TODO(), input)
	if err != nil {
		return false, fmt.Errorf("failed to describe SSM instance information: %v", err)
	}

	// Check if any instance information matches the instance ID
	for _, instanceInfo := range resp.InstanceInformationList {
		if *instanceInfo.InstanceId == instanceID {
			return true, nil
		}
	}

	return false, nil
}

// ssmCheck function, which accepts aws.Config as a parameter
func SsmCheck(cfg aws.Config) error {
	// Step 1: List EC2 instances dynamically
	instanceIDs, err := listEC2Instances(cfg)
	if err != nil {
		return fmt.Errorf("Error listing EC2 instances: %v", err)
	}

	// Step 2: For each instance, check if SSM is registered
	for _, instanceID := range instanceIDs {
		ssmRegistered, err := isSSMRegistered(cfg, instanceID)
		if err != nil {
			log.Printf("Error checking SSM status for instance %s: %v", instanceID, err)
			continue
		}

		if ssmRegistered {
			fmt.Printf("Instance %s is managed by SSM.\n", instanceID)
		} else {
			fmt.Printf("Instance %s is NOT managed by SSM.\n", instanceID)
		}
	}

	return nil
}
