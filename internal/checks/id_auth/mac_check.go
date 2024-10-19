package id_auth

import (
	"context"
	"fmt"
	"log"

	configure "cloud_compliance_checker/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// AuthenticateDeviceByMAC compares the MAC address of the instance with the allowed MAC address.
// Returns nil if the MAC address is valid, otherwise returns an error.
func AuthenticateDeviceByMAC(instanceMAC string, allowedMAC string) error {
	if instanceMAC == allowedMAC {
		return nil // MAC address is allowed, no error.
	}
	// Return an error if the MAC address is not allowed, including both the fetched and allowed MAC addresses in the message.
	return fmt.Errorf("authentication failed: MAC address %s does not match allowed MAC address %s", instanceMAC, allowedMAC)
}

// FetchInstanceMAC uses AWS SDK to retrieve the MAC address of an EC2 instance.
func FetchInstanceMAC(instanceID string, ec2Client *ec2.Client) (string, error) {
	// Describe the EC2 instance by instance ID.
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	// Fetch the instance details.
	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe instance: %w", err)
	}

	// Extract MAC address from network interfaces.
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				// Return the first MAC address we find.
				return *networkInterface.MacAddress, nil
			}
		}
	}

	return "", fmt.Errorf("no MAC address found for instance %s", instanceID)
}

// GetVPCID retrieves the VPC ID from an existing EC2 instance.
func GetVPCID(instanceID string, ec2Client *ec2.Client) (string, error) {
	// Describe the EC2 instance to get its VPC ID.
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe instance: %w", err)
	}

	// Extract the VPC ID from the instance details.
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			return *instance.VpcId, nil
		}
	}

	return "", fmt.Errorf("no VPC ID found for instance %s", instanceID)
}

// GetSecurityGroupIDByName fetches the security group ID by its name.
func GetSecurityGroupIDByName(groupName string, ec2Client *ec2.Client) (string, error) {
	// Describe the security groups with the given group name.
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
		return "", fmt.Errorf("failed to describe security groups: %w", err)
	}

	// Check if the security group was found.
	if len(result.SecurityGroups) == 0 {
		return "", fmt.Errorf("security group %s not found", groupName)
	}

	// Return the ID of the first matching security group.
	return *result.SecurityGroups[0].GroupId, nil
}

// CreateQuarantineSecurityGroup creates a new quarantine security group with no inbound or outbound permissions.
func CreateQuarantineSecurityGroup(vpcID string, ec2Client *ec2.Client) (string, error) {
	// Create the security group with no inbound/outbound rules.
	input := &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("quarantine"),
		Description: aws.String("Quarantine security group with no inbound or outbound traffic"),
		VpcId:       aws.String(vpcID),
	}

	result, err := ec2Client.CreateSecurityGroup(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to create quarantine security group: %w", err)
	}

	log.Printf("Created quarantine security group (ID: %s)\n", *result.GroupId)
	return *result.GroupId, nil
}

// QuarantineInstance moves the instance to a quarantine security group to block its external access.
func QuarantineInstance(instanceID string, quarantineSecurityGroupID string, ec2Client *ec2.Client) error {
	// Associate the quarantine security group with the instance.
	input := &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		Groups:     []string{quarantineSecurityGroupID}, // Apply the quarantine security group.
	}

	_, err := ec2Client.ModifyInstanceAttribute(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to quarantine instance %s: %w", instanceID, err)
	}

	log.Printf("Instance %s has been placed in quarantine (Security Group: %s)\n", instanceID, quarantineSecurityGroupID)
	return nil
}

// CheckMac validates the MAC addresses of EC2 instances and quarantines non-compliant instances.
func CheckMac(cfg aws.Config) error {
	// Create an EC2 client.
	ec2Client := ec2.NewFromConfig(cfg)

	// Attempt to get the quarantine security group ID by its name.
	quarantineSecurityGroupID, err := GetSecurityGroupIDByName("quarantine", ec2Client)
	if err != nil {
		// If the quarantine security group is not found, create it.
		log.Println("Quarantine security group not found, creating it...")

		// Retrieve the VPC ID from one of the EC2 instances.
		instanceIDs, err := ListEC2Instances(ec2Client)
		if err != nil || len(instanceIDs) == 0 {
			log.Fatalf("Failed to retrieve instances for VPC ID: %v", err)
		}

		vpcID, err := GetVPCID(instanceIDs[0], ec2Client)
		if err != nil {
			log.Fatalf("Failed to retrieve the VPC ID: %v", err)
		}

		quarantineSecurityGroupID, err = CreateQuarantineSecurityGroup(vpcID, ec2Client)
		if err != nil {
			log.Fatalf("Failed to create quarantine security group: %v", err)
		}
	}

	// List all EC2 instances from AWS.
	instanceIDs, err := ListEC2Instances(ec2Client)
	if err != nil {
		log.Fatalf("failed to list EC2 instances: %v", err)
	}

	nonCompliant := false

	// Iterate over each EC2 instance retrieved from AWS.
	for _, instanceID := range instanceIDs {
		var allowedMAC string
		for _, ec2Instance := range configure.AppConfig.AWS.EC2Instances {
			if ec2Instance.InstanceID == instanceID {
				allowedMAC = ec2Instance.MACAddress
				break
			}
		}

		// If no allowed MAC address is found in the config, skip this instance.
		if allowedMAC == "" {
			log.Printf("No allowed MAC address found for instance %s in the config\n", instanceID)
			continue
		}

		// Fetch the MAC address of the instance from AWS.
		mac, err := FetchInstanceMAC(instanceID, ec2Client)
		if err != nil {
			log.Printf("Failed to fetch MAC address for instance %s: %v\n", instanceID, err)
			continue
		}

		// Authenticate the instance based on its specific allowed MAC address.
		err = AuthenticateDeviceByMAC(mac, allowedMAC)
		if err != nil {
			// Log the error if MAC is not allowed, displaying both the fetched and allowed MAC addresses.
			log.Printf("Authentication failed for instance %s with fetched MAC address %s: %v\n", instanceID, mac, err)

			// Quarantine the instance by assigning the quarantine security group.
			qErr := QuarantineInstance(instanceID, quarantineSecurityGroupID, ec2Client)
			if qErr != nil {
				log.Printf("Failed to quarantine instance %s: %v\n", instanceID, qErr)
			}

			nonCompliant = true
		} else {
			// If no error, proceed with authenticated instance.
			log.Printf("Instance %s authenticated with MAC address %s\n", instanceID, mac)
		}
	}

	// If any instance was non-compliant, return an error indicating overall non-compliance.
	if nonCompliant {
		return fmt.Errorf("non-compliant: At least one instance failed MAC address authentication and was placed in quarantine")
	}

	log.Println("Compliant: All instances passed MAC address authentication")
	return nil
}

// ListEC2Instances retrieves a list of EC2 instance IDs from AWS.
func ListEC2Instances(ec2Client *ec2.Client) ([]string, error) {
	// Initialize the list of instance IDs.
	var instanceIDs []string

	// Describe all instances in the account.
	input := &ec2.DescribeInstancesInput{}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	// Extract the instance IDs from the result.
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			instanceIDs = append(instanceIDs, *instance.InstanceId)
		}
	}

	return instanceIDs, nil
}
