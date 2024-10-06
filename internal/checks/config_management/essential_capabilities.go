package config_management

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// GetSecurityGroups retrieves the security groups and their associated ports
func GetSecurityGroups(cfg aws.Config) (map[string][]int, error) {
	ec2Client := ec2.NewFromConfig(cfg)
	result, err := ec2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving security groups: %v", err)
	}

	securityGroups := make(map[string][]int)
	for _, group := range result.SecurityGroups {
		var ports []int
		for _, perm := range group.IpPermissions {
			if perm.FromPort != nil {
				ports = append(ports, int(*perm.FromPort))
			}
		}
		securityGroups[*group.GroupId] = ports
	}
	return securityGroups, nil
}

// GetEC2Instances retrieves the list of running EC2 instances
func GetEC2Instances(cfg aws.Config) (map[string]string, error) {
	ec2Client := ec2.NewFromConfig(cfg)
	result, err := ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving EC2 instances: %v", err)
	}

	instances := make(map[string]string)
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			instanceID := *instance.InstanceId
			// Here we could add more details like tags or purpose of the instance for further analysis
			// In this case, we'll just map the ID to a description for simplicity
			instances[instanceID] = "General purpose EC2 instance" // Add more detailed descriptions if needed
		}
	}
	return instances, nil
}

// GetRunningFunctions simulates the list of functions running on the system.
func GetRunningFunctions() []string {
	// Simulated running functions
	return []string{"SSH Access", "HTTP Web Server", "Database Access"} // Simulated for now - replace with real logic
}

// MonitorAWSResources checks for unnecessary AWS services, EC2 instances, and security groups,
// and returns a detailed error message listing the non-compliant resources and functions.
func MonitorAWSResources(cfg aws.Config, essentialConfig *config.MissionEssentialConfig) error {
	var nonCompliantItems []string

	// Get current EC2 instances
	ec2Instances, err := GetEC2Instances(cfg)
	if err != nil {
		return err
	}

	// Get security groups and open ports
	securityGroups, err := GetSecurityGroups(cfg)
	if err != nil {
		return err
	}

	// Get currently running functions (simulated for this example)
	runningFunctions := GetRunningFunctions()

	// List all running functions and check for non-essential functions
	fmt.Println("Currently running functions:")
	for _, function := range runningFunctions {
		if contains(essentialConfig.Functions, function) {
			fmt.Printf("  %s - Compliant\n", function)
		} else {
			fmt.Printf("  %s - Non-Compliant\n", function)
			nonCompliantItems = append(nonCompliantItems, fmt.Sprintf("Non-essential function detected: %s", function))
		}
	}

	// List and check EC2 instances
	fmt.Println("\nCurrently running EC2 instances:")
	for instanceID, description := range ec2Instances {
		if contains(essentialConfig.Functions, description) {
			fmt.Printf("  %s - Compliant (%s)\n", instanceID, description)
		} else {
			reason := fmt.Sprintf("Purpose: %s does not match mission-essential functions", description)
			fmt.Printf("  %s - Non-Compliant (%s)\n", instanceID, reason)
			nonCompliantItems = append(nonCompliantItems, fmt.Sprintf("Non-essential EC2 instance detected: %s. Reason: %s", instanceID, reason))
		}
	}

	// List and check Security Groups for non-essential open ports
	fmt.Println("\nOpen ports in Security Groups:")
	for groupID, ports := range securityGroups {
		for _, port := range ports {
			if contains(essentialConfig.Ports, fmt.Sprintf("%d", port)) {
				fmt.Printf("  Security Group %s, Port %d - Compliant\n", groupID, port)
			} else {
				fmt.Printf("  Security Group %s, Port %d - Non-Compliant\n", groupID, port)
				nonCompliantItems = append(nonCompliantItems, fmt.Sprintf("Non-essential open port detected in security group %s: %d", groupID, port))
			}
		}
	}

	// If non-compliant resources are found, return a detailed error
	if len(nonCompliantItems) > 0 {
		return fmt.Errorf(strings.Join(nonCompliantItems, "\n"))
	}

	return nil
}

// contains checks if a slice contains a particular string
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// RunAWSResourceReview runs the AWS resource review and returns detailed information on non-compliant resources
func RunAWSResourceReview(cfg aws.Config) error {
	// Access mission-essential configuration from the loaded config
	essentialConfig := config.AppConfig.AWS.MissionEssentialConfig

	fmt.Println("Starting AWS Resource Capability Review")
	fmt.Println("Mission-essential capabilities being enforced...")
	fmt.Printf("  Functions: %v\n", essentialConfig.Functions)
	fmt.Printf("  Ports: %v\n", essentialConfig.Ports)
	fmt.Println("---------------------------------------")

	// Monitor and handle non-essential AWS resources (EC2 instances, open ports)
	err := MonitorAWSResources(cfg, &essentialConfig)
	if err != nil {
		fmt.Println("Non-compliant resources found:")
		fmt.Printf("%v\n", err)
		return err
	}

	fmt.Println("AWS Resource Capability Review completed successfully")
	return nil
}