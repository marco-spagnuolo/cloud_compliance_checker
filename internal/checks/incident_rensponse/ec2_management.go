package incident_response

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Function to launch an attacker EC2 instance
func launchInstanceIfNotExists(cfg aws.Config, role string) (string, string, error) {
	// Check if an instance with the given role already exists
	instanceID, ipAddress, err := findInstanceByTag(cfg, role)
	if err != nil {
		return "", "", err
	}

	// If an instance is found, return the existing instance ID and IP address
	if instanceID != "" {
		fmt.Printf("%s instance found with ID: %s and IP: %s\n", strings.Title(role), instanceID, ipAddress)
		return instanceID, ipAddress, nil
	}

	// Otherwise, launch a new instance
	fmt.Printf("No %s instance found, launching a new one...\n", role)
	svc := ec2.NewFromConfig(cfg)
	attackerConfig := config.AppConfig.AWS.AttackerInstance

	keyPath := filepath.Join("internal", "checks", "incident_rensponse", "attackerkey.pem")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("SSH key not found at path: %s", keyPath)
	}

	// Define the instance parameters
	runInstancesInput := &ec2.RunInstancesInput{
		ImageId:      aws.String(attackerConfig.AMI),
		InstanceType: ec2types.InstanceType(attackerConfig.InstanceType),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		KeyName:      aws.String(attackerConfig.KeyName),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeInstance,
				Tags: []ec2types.Tag{
					{Key: aws.String("Role"), Value: aws.String(role)},
					{Key: aws.String("Name"), Value: aws.String(fmt.Sprintf("%s-instance", role))},
				},
			},
		},
		NetworkInterfaces: []ec2types.InstanceNetworkInterfaceSpecification{
			{
				AssociatePublicIpAddress: aws.Bool(true),
				DeviceIndex:              aws.Int32(0),
				SubnetId:                 aws.String("subnet-0ff34827526a146d1"),
				Groups: []string{
					attackerConfig.SecurityGroup,
				},
			},
		},
	}

	// Launch the instance
	result, err := svc.RunInstances(context.TODO(), runInstancesInput)
	if err != nil {
		return "", "", fmt.Errorf("failed to launch %s instance: %v", role, err)
	}

	instanceID = *result.Instances[0].InstanceId

	// Allow SSH access to the security group (for attacker instance)
	if role == "attacker" {
		err = allowSSHAccess(cfg, attackerConfig.SecurityGroup)
		if err != nil {
			return "", "", fmt.Errorf("failed to configure SSH access: %v", err)
		}
	}

	// // Poll until the public IP address is available
	// for i := 0; i < 10; i++ {
	// 	describeInstancesInput := &ec2.DescribeInstancesInput{
	// 		InstanceIds: []string{instanceID},
	// 	}
	// 	describeInstancesOutput, err := svc.DescribeInstances(context.TODO(), describeInstancesInput)
	// 	if err != nil {
	// 		return "", "", fmt.Errorf("failed to describe instance: %v", err)
	// 	}

	// 	if len(describeInstancesOutput.Reservations) > 0 &&
	// 		len(describeInstancesOutput.Reservations[0].Instances) > 0 {
	// 		instance := describeInstancesOutput.Reservations[0].Instances[0]
	// 		if instance.PublicIpAddress != nil {
	// 			ipAddress = *instance.PublicIpAddress
	// 			fmt.Printf("Launched %s instance with ID: %s and IP: %s\n", role, instanceID, ipAddress)
	// 			break
	// 		}
	// 	}

	// 	// Wait before trying again
	// 	time.Sleep(10 * time.Second)
	// }

	if ipAddress == "" {
		return "", "", fmt.Errorf("%s instance launched but no public IP address assigned after 10 attempts", role)
	}

	return instanceID, ipAddress, nil
}

// Isolate EC2 instance by modifying security group rules
func isolateEC2Instance(cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)
	describeInstancesInput := &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}}
	describeInstancesOutput, err := svc.DescribeInstances(context.TODO(), describeInstancesInput)
	if err != nil {
		return fmt.Errorf("unable to describe instance: %v", err)
	}

	if len(describeInstancesOutput.Reservations) == 0 {
		return fmt.Errorf("no instance found with ID: %s", instanceID)
	}

	securityGroups := describeInstancesOutput.Reservations[0].Instances[0].SecurityGroups
	for _, sg := range securityGroups {
		// Revoke ingress and egress rules to isolate the instance
		err = revokeIngressEgressRules(svc, sg.GroupId)
		if err != nil {
			return fmt.Errorf("unable to revoke rules for group %s: %v", *sg.GroupId, err)
		}
	}
	return nil
}

// Function to unblock an EC2 instance (restore security group rules)
func unblockEC2Instance(cfg aws.Config, instanceID string) error {
	fmt.Printf("Starting unblocking of EC2 instance: %s...\n", instanceID)
	svc := ec2.NewFromConfig(cfg)

	// Get the security groups associated with the instance
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}
	describeInstancesOutput, err := svc.DescribeInstances(context.TODO(), describeInstancesInput)
	if err != nil {
		return fmt.Errorf("unable to describe instances: %v", err)
	}

	if len(describeInstancesOutput.Reservations) == 0 || len(describeInstancesOutput.Reservations[0].Instances) == 0 {
		return fmt.Errorf("instance not found: %s", instanceID)
	}

	instance := describeInstancesOutput.Reservations[0].Instances[0]
	securityGroupIDs := instance.SecurityGroups

	// Restore security group ingress and egress rules to unblock the instance
	for _, sg := range securityGroupIDs {
		// Check and restore ingress rules
		err := restoreIngressRules(svc, sg.GroupId)
		if err != nil {
			return fmt.Errorf("unable to restore ingress rules for group %s: %v", *sg.GroupId, err)
		}

		// Check and restore egress rules
		err = restoreEgressRules(svc, sg.GroupId)
		if err != nil {
			return fmt.Errorf("unable to restore egress rules for group %s: %v", *sg.GroupId, err)
		}
	}

	fmt.Printf("EC2 instance %s has been unblocked successfully.\n", instanceID)
	return nil
}

func findInstanceByTag(cfg aws.Config, role string) (string, string, error) {
	svc := ec2.NewFromConfig(cfg)

	describeInstancesInput := &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("tag:Role"),
				Values: []string{role},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running", "pending"},
			},
		},
	}
	describeInstancesOutput, err := svc.DescribeInstances(context.TODO(), describeInstancesInput)
	if err != nil {
		return "", "", fmt.Errorf("failed to describe instances: %v", err)
	}

	for _, reservation := range describeInstancesOutput.Reservations {
		for _, instance := range reservation.Instances {
			if instance.InstanceId != nil && instance.PublicIpAddress != nil {
				return *instance.InstanceId, *instance.PublicIpAddress, nil
			}
		}
	}

	return "", "", fmt.Errorf("no instances found")
}

// Function to unblock and make the victim instance vulnerable before the attack
func unblockAndMakeVulnerable(cfg aws.Config, instanceID, ipAddress string) error {
	// Step 1: Unblock the victim instance by restoring security group rules
	fmt.Println("Unblocking victim instance...")
	err := unblockEC2Instance(cfg, instanceID)
	if err != nil {
		return fmt.Errorf("error unblocking EC2 instance: %v", err)
	}
	fmt.Println("Victim instance unblocked successfully.")

	// Step 2: Make the victim instance more vulnerable (enable password auth and remove limits)
	fmt.Println("Making the victim more vulnerable to brute force attacks...")
	err = makeVictimVulnerable(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to make victim vulnerable: %v", err)
	}
	fmt.Println("Victim instance made vulnerable.")
	return nil
}

// Enable password authentication, remove rate limiting, and create brute_force user if not exists
func makeVictimVulnerable(ipAddress string) error {
	enablePasswordAuthCommand := `
		# Enable password authentication and remove rate limiting
		sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config &&
		sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 1000/' /etc/ssh/sshd_config &&  
		sudo sed -i 's/#LoginGraceTime 2m/LoginGraceTime 10m/' /etc/ssh/sshd_config &&  
		sudo systemctl restart sshd &&
		
		# Check if brute_force user exists, and create it if not
		if id "brute" &>/dev/null; then
		    echo "User brute already exists, skipping creation."
		else
		    sudo useradd -m -s /bin/bash brute &&
		    echo 'brute:poppypig' | sudo chpasswd &&
		    sudo usermod -aG sudo brute &&
		    echo "User brute created successfully."
		fi
	`
	log.Printf("Executing command to make victim instance at %s vulnerable, including creating brute user if necessary...", ipAddress)
	s, err := executeSSHCommandWithOutput(ipAddress, enablePasswordAuthCommand)
	log.Println(s)
	if err != nil {
		return fmt.Errorf("failed to make victim vulnerable: %v", err)
	}
	return nil

}
