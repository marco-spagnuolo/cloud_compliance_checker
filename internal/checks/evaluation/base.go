package evaluation

import (
	"cloud_compliance_checker/internal/checks/access_control/device"
	"cloud_compliance_checker/internal/checks/access_control/iam"
	"cloud_compliance_checker/internal/checks/access_control/network"
	"cloud_compliance_checker/internal/checks/access_control/securitygroup"
	"cloud_compliance_checker/internal/checks/access_control/system"
	"cloud_compliance_checker/internal/checks/audit_and_accountability"
	"cloud_compliance_checker/internal/checks/config_management"
	"cloud_compliance_checker/internal/checks/id_auth"
	"cloud_compliance_checker/internal/checks/protection"
	"cloud_compliance_checker/internal/checks/risk_assesment"
	"cloud_compliance_checker/internal/checks/security_assessment"
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// evaluateCriteria evaluates the criteria for a given instance and returns the compliance result
func evaluateCriteria(svc configserviceiface.ConfigServiceAPI, instance *ec2.Instance, criteria models.Criteria, iamClient iamiface.IAMAPI, ec2Client ec2iface.EC2API, sess *session.Session, cloudTrailClient cloudtrailiface.CloudTrailAPI) models.ComplianceResult {
	switch criteria.CheckFunction {
	case "CheckSecurityGroup":
		return securitygroup.CheckSecurityGroup(instance)
	case "CheckIAMRoles":
		return iam.CheckIAMRoles(instance)
	case "CheckFlowLogs":
		return network.CheckFlowLogs(ec2Client, instance)
	case "CheckSeparateDuties":
		return iam.CheckSeparateDuties(iamClient, instance)
	case "CheckLeastPrivilege":
		return iam.CheckLeastPrivilege(iamClient, instance)
	case "CheckNonPrivilegedAccounts":
		return iam.CheckNonPrivilegedAccounts(iamClient, instance)
	case "CheckPreventPrivilegedFunctions":
		return iam.CheckPreventPrivilegedFunctions(iamClient, instance)
	case "CheckLogonAttempts":
		return system.CheckLogonAttempts(instance)
	case "CheckPrivacyNotices":
		return system.CheckPrivacyNotices(instance)
	case "CheckSessionLock":
		return system.CheckSessionLock(instance)
	case "CheckSessionTermination":
		return system.CheckSessionTermination(instance)
	case "CheckRemoteAccessMonitoring":
		return network.CheckRemoteAccessMonitoring(instance)
	case "CheckRemoteAccessEncryption":
		return network.CheckRemoteAccessEncryption(instance)
	case "CheckRemoteAccessRouting":
		return network.CheckRemoteAccessRouting(ec2Client, instance)
	case "CheckRemoteExecutionAuthorization":
		return iam.CheckRemoteExecutionAuthorization(iamClient, instance)
	case "CheckWirelessAccessAuthorization":
		return network.CheckWirelessAccessAuthorization(instance)
	case "CheckWirelessAccessProtection":
		return network.CheckWirelessAccessProtection(instance)
	case "CheckMobileDeviceConnection":
		return device.CheckMobileDeviceConnection(instance)
	case "CheckMobileDeviceEncryption":
		return device.CheckMobileDeviceEncryption(instance)
	case "CheckExternalSystemConnections":
		return device.CheckExternalSystemConnections(instance)
	case "CheckPortableStorageUse":
		return device.CheckPortableStorageUse(instance)
	case "CheckPublicCUIControl":
		return device.CheckPublicCUIControl(instance)
	case "CheckAuditLogs":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditLogs()
	case "CheckUserTraceability":
		return audit_and_accountability.NewAuditAndAccountability().CheckUserTraceability()
	case "CheckLoggedEventsReview":
		return audit_and_accountability.NewAuditAndAccountability().CheckLoggedEventsReview()
	case "CheckAuditLoggingFailure":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditLoggingFailure()
	case "CheckAuditCorrelation":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditCorrelation()
	case "CheckAuditReduction":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditReduction()
	case "CheckTimeSynchronization":
		return audit_and_accountability.NewAuditAndAccountability().CheckTimeSynchronization()
	case "CheckSecurityConfiguration":
		return config_management.CheckSecurityConfiguration(svc)
	case "CheckConfigurationChanges":
		return config_management.CheckConfigurationChanges(svc)
	case "CheckSecurityImpactAnalysis":
		return config_management.CheckSecurityImpactAnalysis(svc)
	case "CheckAccessRestrictions":
		return config_management.CheckAccessRestrictions(svc)
	case "CheckLeastFunctionality":
		return config_management.CheckLeastFunctionality(svc)
	case "CheckNonessentialFunctions":
		return config_management.CheckNonessentialFunctions(svc)
	case "CheckSoftwarePolicies":
		return config_management.CheckSoftwarePolicies(svc)
	case "CheckUserInstalledSoftware":
		return config_management.CheckUserInstalledSoftware(svc)
	case "CheckBoundaryProtection":
		return protection.CheckBoundaryProtection(sess)
	case "CheckCryptographicProtection":
		return protection.CheckCryptographicProtection(sess)
	case "CheckInformationTransmissionProtection":
		return protection.CheckInformationTransmissionProtection(sess)
	case "CheckSystemUsers":
		return id_auth.CheckSystemUsers(iamClient, cloudTrailClient, ec2Client)
	case "CheckAuthentication":
		return id_auth.CheckAuthentication(iamClient)
	case "CheckMFA":
		return id_auth.CheckMFA(iamClient)
	case "CheckReplayResistantAuthentication":
		return id_auth.CheckReplayResistantAuthentication()
	case "CheckIdentifierReusePrevention":
		return id_auth.CheckIdentifierReusePrevention(iamClient)
	case "CheckIdentifierDisabling":
		return id_auth.CheckIdentifierDisabling(iamClient)
	case "CheckPasswordComplexity":
		return id_auth.CheckPasswordComplexity(iamClient)
	case "CheckPasswordReuseProhibition":
		return id_auth.CheckPasswordReuseProhibition(iamClient)
	case "CheckTemporaryPasswordUsage":
		return id_auth.CheckTemporaryPasswordUsage(iamClient)
	case "CheckPasswordEncryption":
		return id_auth.CheckPasswordEncryption(iamClient)
	case "CheckObscuredFeedback":
		return id_auth.CheckObscuredFeedback(iamClient)
	case "CheckRiskAssessment":
		return risk_assesment.CheckRiskAssessment(sess)
	case "CheckVulnerabilityScan":
		return risk_assesment.CheckVulnerabilityScan(sess)
	case "CheckSecurityAssessmentProcedures":
		return security_assessment.CheckSecurityAssessmentProcedures(sess)
	case "CheckSecurityControlAssessments":
		return security_assessment.CheckSecurityControlAssessments(sess)
	default:
		return models.ComplianceResult{
			Description: criteria.Description,
			Status:      "UNKNOWN",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}
}

// CheckCompliance runs all compliance checks on the given instance and returns the total score
func CheckCompliance(instance *ec2.Instance, controls models.NISTControls, iamClient iamiface.IAMAPI, ec2Client ec2iface.EC2API, cloudTrailClient cloudtrailiface.CloudTrailAPI) int {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)
	score := 110
	for _, control := range controls.Controls {
		for _, criteria := range control.Criteria {
			result := evaluateCriteria(svc, instance, criteria, iamClient, ec2Client, sess, cloudTrailClient)
			fmt.Printf("Check: %s, Result: %s, Impact: %d\n", criteria.CheckFunction, result.Status, result.Impact) // Debugging line
			score -= result.Impact
		}
	}
	return score
}
