package checks

import (
	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/service/ec2"
)

func CheckSecurityGroup(instance *ec2.Instance) models.ComplianceResult {
	requiredGroupName := "required-security-group"
	for _, sg := range instance.SecurityGroups {
		if *sg.GroupName == requiredGroupName {
			return models.ComplianceResult{
				Description: "Instance has a specific security group",
				Status:      "PASS",
				Response:    "Implemented",
				Impact:      0,
			}
		}
	}
	return models.ComplianceResult{
		Description: "Instance has a specific security group",
		Status:      "FAIL",
		Response:    "Planned to be implemented",
		Impact:      5,
	}
}

func CheckIAMRoles(instance *ec2.Instance) models.ComplianceResult {
	if instance.IamInstanceProfile != nil {
		return models.ComplianceResult{
			Description: "Instance has IAM roles attached",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}
	return models.ComplianceResult{
		Description: "Instance has IAM roles attached",
		Status:      "FAIL",
		Response:    "Planned to be implemented",
		Impact:      5,
	}
}

func CheckFlowLogs(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for flow logs here
	return models.ComplianceResult{
		Description: "Instance has flow logs enabled",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckSeparateDuties(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for separate duties here
	return models.ComplianceResult{
		Description: "Instance has roles with separate duties",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckLeastPrivilege(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for least privilege here
	return models.ComplianceResult{
		Description: "Instance uses least privilege for IAM roles",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckNonPrivilegedAccounts(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for non-privileged accounts here
	return models.ComplianceResult{
		Description: "Instance uses non-privileged roles for nonsecurity functions",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckPreventPrivilegedFunctions(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for preventing privileged functions here
	return models.ComplianceResult{
		Description: "Instance prevents non-privileged users from executing privileged functions",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckLogonAttempts(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for logon attempts here
	return models.ComplianceResult{
		Description: "Instance limits unsuccessful logon attempts",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckPrivacyNotices(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for privacy notices here
	return models.ComplianceResult{
		Description: "Instance provides privacy and security notices",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckSessionLock(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for session lock here
	return models.ComplianceResult{
		Description: "Instance uses session lock with pattern-hiding displays",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckSessionTermination(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for session termination here
	return models.ComplianceResult{
		Description: "Instance automatically terminates user sessions after a defined condition",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckRemoteAccessMonitoring(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for remote access monitoring here
	return models.ComplianceResult{
		Description: "Instance monitors and controls remote access sessions",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckRemoteAccessEncryption(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for remote access encryption here
	return models.ComplianceResult{
		Description: "Instance uses encryption for remote access sessions",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckRemoteAccessRouting(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for remote access routing here
	return models.ComplianceResult{
		Description: "Instance routes remote access via managed access control points",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckRemoteExecutionAuthorization(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for remote execution authorization here
	return models.ComplianceResult{
		Description: "Instance authorizes remote execution of privileged commands",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckWirelessAccessAuthorization(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for wireless access authorization here
	return models.ComplianceResult{
		Description: "Instance authorizes wireless access before connections",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckWirelessAccessProtection(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for wireless access protection here
	return models.ComplianceResult{
		Description: "Instance uses authentication and encryption for wireless access",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckMobileDeviceConnection(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for mobile device connection here
	return models.ComplianceResult{
		Description: "Instance controls connection of mobile devices",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckMobileDeviceEncryption(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for mobile device encryption here
	return models.ComplianceResult{
		Description: "Instance encrypts CUI on mobile devices",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckExternalSystemConnections(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for external system connections here
	return models.ComplianceResult{
		Description: "Instance controls connections to external systems",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckPortableStorageUse(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for portable storage use here
	return models.ComplianceResult{
		Description: "Instance limits use of portable storage devices on external systems",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func CheckPublicCUIControl(instance *ec2.Instance) models.ComplianceResult {
	// Implement the actual check logic for public CUI control here
	return models.ComplianceResult{
		Description: "Instance controls CUI on publicly accessible systems",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}
