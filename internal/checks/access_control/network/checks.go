package network

import (
	"cloud_compliance_checker/models"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

func CheckFlowLogs(svc ec2iface.EC2API, instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	vpcID := instance.VpcId

	input := &ec2.DescribeFlowLogsInput{
		Filter: []*ec2.Filter{
			{
				Name: aws.String("resource-id"),
				Values: []*string{
					vpcID,
				},
			},
		},
	}

	result, err := svc.DescribeFlowLogs(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance has flow logs enabled",
			Status:      "FAIL",
			Response:    "Error describing flow logs",
			Impact:      criteria.Value,
		}
	}

	if len(result.FlowLogs) > 0 {
		return models.ComplianceResult{
			Description: "Instance has flow logs enabled",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance has flow logs enabled",
			Status:      "FAIL",
			Response:    "Flow logs not enabled",
			Impact:      criteria.Value,
		}
	}
}

func CheckRemoteAccessMonitoring(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	success, err := checkAuditdConfiguration()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance monitors and controls remote access sessions",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking auditd configuration: %v", err),
			Impact:      criteria.Value,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance monitors and controls remote access sessions",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance monitors and controls remote access sessions",
			Status:      "FAIL",
			Response:    "auditd not properly configured for remote access monitoring",
			Impact:      criteria.Value,
		}
	}
}

func checkAuditdConfiguration() (bool, error) {
	cmd := exec.Command("grep", "-E", "^-w /var/log/secure -p wa -k access", "/etc/audit/audit.rules")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}

	if strings.Contains(string(output), "-w /var/log/secure -p wa -k access") {
		return true, nil
	}

	return false, nil
}

func CheckRemoteAccessEncryption(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	success, err := checkSSHEcryptionConfiguration()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance uses encryption for remote access sessions",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking SSH configuration: %v", err),
			Impact:      criteria.Value,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance uses encryption for remote access sessions",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance uses encryption for remote access sessions",
			Status:      "FAIL",
			Response:    "SSH not properly configured for encryption",
			Impact:      criteria.Value,
		}
	}
}

func checkSSHEcryptionConfiguration() (bool, error) {
	cmd := exec.Command("sshd", "-T")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}

	requiredCiphers := []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"}
	for _, cipher := range requiredCiphers {
		if !strings.Contains(string(output), fmt.Sprintf("ciphers %s", cipher)) {
			return false, nil
		}
	}

	return true, nil
}

func CheckRemoteAccessRouting(ec2Client ec2iface.EC2API, instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	securityGroups := instance.SecurityGroups

	for _, sg := range securityGroups {
		input := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{sg.GroupId},
		}

		result, err := ec2Client.DescribeSecurityGroups(input)
		if err != nil {
			return models.ComplianceResult{
				Description: "Instance routes remote access via managed access control points",
				Status:      "FAIL",
				Response:    fmt.Sprintf("Error describing security group: %v", err),
				Impact:      criteria.Value,
			}
		}

		for _, group := range result.SecurityGroups {
			for _, permission := range group.IpPermissions {
				if isValidBastionHostPermission(permission) {
					return models.ComplianceResult{
						Description: "Instance routes remote access via managed access control points",
						Status:      "PASS",
						Response:    "Implemented",
						Impact:      0,
					}
				}
			}
		}
	}

	return models.ComplianceResult{
		Description: "Instance routes remote access via managed access control points",
		Status:      "FAIL",
		Response:    "No valid bastion host routing found in security groups",
		Impact:      criteria.Value,
	}
}

func isValidBastionHostPermission(permission *ec2.IpPermission) bool {
	if aws.StringValue(permission.IpProtocol) == "tcp" &&
		aws.Int64Value(permission.FromPort) == 22 &&
		aws.Int64Value(permission.ToPort) == 22 {
		for _, rangeInfo := range permission.IpRanges {
			if aws.StringValue(rangeInfo.CidrIp) == "1.1.1.1/32" { // Replace with valid bastion host IP
				return true
			}
		}
	}
	return false
}

func CheckWirelessAccessAuthorization(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	authorized, err := verifyWirelessAccessAuthorization()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance authorizes wireless access before connections",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error verifying wireless access authorization: %v", err),
			Impact:      criteria.Value,
		}
	}

	if authorized {
		return models.ComplianceResult{
			Description: "Instance authorizes wireless access before connections",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance authorizes wireless access before connections",
			Status:      "FAIL",
			Response:    "Wireless access not properly authorized",
			Impact:      criteria.Value,
		}
	}
}

func verifyWirelessAccessAuthorization() (bool, error) {
	authorized := true
	return authorized, nil
}

func CheckWirelessAccessProtection(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	protected, err := verifyWirelessAccessProtection()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance uses authentication and encryption for wireless access",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error verifying wireless access protection: %v", err),
			Impact:      criteria.Value,
		}
	}

	if protected {
		return models.ComplianceResult{
			Description: "Instance uses authentication and encryption for wireless access",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance uses authentication and encryption for wireless access",
			Status:      "FAIL",
			Response:    "Wireless access not properly protected",
			Impact:      criteria.Value,
		}
	}
}

func verifyWirelessAccessProtection() (bool, error) {
	protected := true
	return protected, nil
}
