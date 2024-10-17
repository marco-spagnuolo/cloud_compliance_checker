package protection

import (
	"context"
	"fmt"
	"log"

	"cloud_compliance_checker/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// CheckDenyByDefaultSecurityGroup checks Security Groups to enforce a deny-by-default policy,
// but allows exceptions based on the allowed ports defined in the config.
func CheckDenyByDefaultSecurityGroup(cfg aws.Config) error {
	awsConfig := config.AppConfig.AWS
	ctx := context.TODO()
	ec2Svc := ec2.NewFromConfig(cfg)

	// Describe all Security Groups
	result, err := ec2Svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return fmt.Errorf("failed to describe security groups: %v", err)
	}

	for _, sg := range result.SecurityGroups {
		log.Printf("Checking Security Group: %s (%s)\n", *sg.GroupName, *sg.GroupId)

		// Get allowed ports from the config for the security group
		allowedIngressPorts, allowedEgressPorts := getAllowedPortsForSecurityGroup(awsConfig, *sg.GroupName)

		// Check inbound rules
		if hasInvalidAllowAllRule(sg.IpPermissions, allowedIngressPorts) {
			return fmt.Errorf("Security Group %s has inbound allow-all rules without valid exception; deny-by-default policy not enforced", *sg.GroupId)
		}

		// Check outbound rules
		if hasInvalidAllowAllRule(sg.IpPermissionsEgress, allowedEgressPorts) {
			return fmt.Errorf("Security Group %s has outbound allow-all rules without valid exception; deny-by-default policy not enforced", *sg.GroupId)
		}
	}

	log.Println("All security groups enforce deny-by-default policy.")
	return nil
}

// getAllowedPortsForSecurityGroup retrieves the allowed ingress and egress ports from the configuration.
func getAllowedPortsForSecurityGroup(awsConfig config.AWSConfig, sgName string) ([]int32, []int32) {
	for _, sg := range awsConfig.SecurityGroups {
		if sg.Name == sgName {
			// Return allowed ingress and egress ports from the config
			allowedIngressPorts := intSliceToInt32Slice(sg.AllowedIngressPorts)
			allowedEgressPorts := intSliceToInt32Slice(sg.AllowedEgressPorts)
			return allowedIngressPorts, allowedEgressPorts
		}
	}
	return []int32{}, []int32{} // Return empty slices if the security group is not found in the config
}

// hasInvalidAllowAllRule checks if a rule allows all traffic (0.0.0.0/0 or ::/0) without valid exceptions.
func hasInvalidAllowAllRule(permissions []types.IpPermission, allowedPorts []int32) bool {
	for _, permission := range permissions {
		if isAllowAllPermission(permission) && !isAllowByException(permission, allowedPorts) {
			return true
		}
	}
	return false
}

// isAllowAllPermission checks if a permission allows traffic from 0.0.0.0/0 or ::/0.
func isAllowAllPermission(permission types.IpPermission) bool {
	for _, ipRange := range permission.IpRanges {
		if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
			return true
		}
	}
	for _, ipv6Range := range permission.Ipv6Ranges {
		if ipv6Range.CidrIpv6 != nil && *ipv6Range.CidrIpv6 == "::/0" {
			return true
		}
	}
	return false
}

// isAllowByException checks if a permission has restrictions (e.g., specific ports) defined in the config.
func isAllowByException(permission types.IpPermission, allowedPorts []int32) bool {
	// Check if the allowed ports from config match the permission ports
	for _, port := range allowedPorts {
		if permission.FromPort != nil && permission.ToPort != nil && *permission.FromPort == port && *permission.ToPort == port {
			return true
		}
	}
	return false
}

// intSliceToInt32Slice converts a slice of int to a slice of int32.
func intSliceToInt32Slice(ports []int) []int32 {
	int32Ports := make([]int32, len(ports))
	for i, port := range ports {
		int32Ports[i] = int32(port)
	}
	return int32Ports
}
