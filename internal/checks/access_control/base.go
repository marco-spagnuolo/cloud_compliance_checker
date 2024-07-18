package checks

import (
	"cloud_compliance_checker/internal/checks/access_control/device"
	"cloud_compliance_checker/internal/checks/access_control/iam"
	"cloud_compliance_checker/internal/checks/access_control/network"
	"cloud_compliance_checker/internal/checks/access_control/securitygroup"
	"cloud_compliance_checker/internal/checks/access_control/system"
	"cloud_compliance_checker/internal/utils"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// ComplianceResult rappresenta il risultato di una verifica di conformità
type ComplianceResult struct {
	Description string
	Status      string
	Response    string
	Impact      int
}

// evaluateCriteria valuta i criteri di conformità per un'istanza EC2
func EvaluateCriteria(instance *ec2.Instance, criteria utils.Criteria, ec2Client ec2iface.EC2API, iamClient iamiface.IAMAPI) ComplianceResult {
	switch criteria.CheckFunction {
	case "CheckSecurityGroup":
		result := securitygroup.CheckSecurityGroup(instance)
		return ComplianceResult(result)
	case "CheckIAMRoles":
		result := iam.CheckIAMRoles(instance)
		return ComplianceResult(result)
	case "CheckFlowLogs":
		result := network.CheckFlowLogs(ec2Client, instance)
		return ComplianceResult(result)
	case "CheckSeparateDuties":
		result := iam.CheckSeparateDuties(iamClient, instance)
		return ComplianceResult(result)
	case "CheckLeastPrivilege":
		result := iam.CheckLeastPrivilege(iamClient, instance)
		return ComplianceResult(result)
	case "CheckNonPrivilegedAccounts":
		result := iam.CheckNonPrivilegedAccounts(iamClient, instance)
		return ComplianceResult(result)
	case "CheckPreventPrivilegedFunctions":
		result := iam.CheckPreventPrivilegedFunctions(iamClient, instance)
		return ComplianceResult(result)
	case "CheckLogonAttempts":
		result := system.CheckLogonAttempts(instance)
		return ComplianceResult(result)
	case "CheckPrivacyNotices":
		result := system.CheckPrivacyNotices(instance)
		return ComplianceResult(result)
	case "CheckSessionLock":
		result := system.CheckSessionLock(instance)
		return ComplianceResult(result)
	case "CheckSessionTermination":
		result := system.CheckSessionTermination(instance)
		return ComplianceResult(result)
	case "CheckRemoteAccessMonitoring":
		result := network.CheckRemoteAccessMonitoring(instance)
		return ComplianceResult(result)
	case "CheckRemoteAccessEncryption":
		result := network.CheckRemoteAccessEncryption(instance)
		return ComplianceResult(result)
	case "CheckRemoteAccessRouting":
		result := network.CheckRemoteAccessRouting(ec2Client, instance)
		return ComplianceResult(result)
	case "CheckRemoteExecutionAuthorization":
		result := iam.CheckRemoteExecutionAuthorization(iamClient, instance)
		return ComplianceResult(result)
	case "CheckWirelessAccessAuthorization":
		result := network.CheckWirelessAccessAuthorization(instance)
		return ComplianceResult(result)
	case "CheckWirelessAccessProtection":
		result := network.CheckWirelessAccessProtection(instance)
		return ComplianceResult(result)
	case "CheckMobileDeviceConnection":
		result := device.CheckMobileDeviceConnection(instance)
		return ComplianceResult(result)
	case "CheckMobileDeviceEncryption":
		result := device.CheckMobileDeviceEncryption(instance)
		return ComplianceResult(result)
	case "CheckExternalSystemConnections":
		result := device.CheckExternalSystemConnections(instance)
		return ComplianceResult(result)
	case "CheckPortableStorageUse":
		result := device.CheckPortableStorageUse(instance)
		return ComplianceResult(result)
	case "CheckPublicCUIControl":
		result := device.CheckPublicCUIControl(instance)
		return ComplianceResult(result)
	default:
		return ComplianceResult{
			Description: criteria.Description,
			Status:      "UNKNOWN",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}
}

// CheckCompliance verifica la conformità di un'istanza EC2 rispetto ai controlli NIST e restituisce un punteggio
func CheckCompliance(instance *ec2.Instance, controls utils.NISTControls, ec2Client ec2iface.EC2API, iamClient iamiface.IAMAPI) int {
	score := 110
	for _, control := range controls.Controls {
		for _, criteria := range control.Criteria {
			result := EvaluateCriteria(instance, criteria, ec2Client, iamClient)
			score -= result.Impact
		}
	}
	return score
}
