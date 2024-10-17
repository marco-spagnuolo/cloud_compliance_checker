package protection

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// CheckCollaborativeDeviceSettings checks EC2 instances for conferencing software or remote desktop configurations that may activate collaborative devices.
// 03.13.12
func CheckCollaborativeDeviceSettings(cfg aws.Config) error {
	ctx := context.TODO()
	ec2Svc := ec2.NewFromConfig(cfg)

	// Describe all EC2 instances
	result, err := ec2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe EC2 instances: %v", err)
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			log.Printf("Checking EC2 Instance: %s\n", *instance.InstanceId)

			// Check user data for indications of collaborative device configurations
			attrOutput, err := ec2Svc.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
				InstanceId: instance.InstanceId,
				Attribute:  types.InstanceAttributeNameUserData,
			})
			if err != nil {
				return fmt.Errorf("failed to describe instance attribute: %v", err)
			}
			if attrOutput.UserData != nil && attrOutput.UserData.Value != nil {
				userData, err := base64.StdEncoding.DecodeString(*attrOutput.UserData.Value)
				if err != nil {
					return fmt.Errorf("failed to decode EC2 user data: %v", err)
				}
				if containsCollaborativeSoftware(string(userData)) {
					return fmt.Errorf("EC2 instance %s contains conferencing or remote desktop software in user data, review configuration to prohibit remote activation of devices", *instance.InstanceId)
				}
			}

			// Optionally, check installed software or security group rules (e.g., for RDP or remote desktop configurations)
		}
	}

	log.Println("Collaborative device settings check completed successfully.")
	return nil
}

// containsCollaborativeSoftware checks if user data contains collaborative software configurations.
func containsCollaborativeSoftware(userData string) bool {
	// Example: Check for common conferencing software (Zoom, Microsoft Teams, etc.)
	collaborativeKeywords := []string{"zoom", "teams", "conferencing", "webcam", "microphone", "remote desktop"}
	for _, keyword := range collaborativeKeywords {
		if strings.Contains(strings.ToLower(userData), keyword) {
			return true
		}
	}
	return false
}
