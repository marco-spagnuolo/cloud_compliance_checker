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
	"log"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// EvaluateAssets evaluates all assets and returns the compliance results *
func EvaluateAssets(assets []models.Asset, controls models.NISTControls,
	iamClient iamiface.IAMAPI, ec2Client ec2iface.EC2API, sess *session.Session, cloudTrailClient cloudtrailiface.CloudTrailAPI) []models.Score {
	var results []models.Score
	for _, asset := range assets {
		score := CheckInstance(asset.Instance, controls, iamClient, ec2Client, sess, cloudTrailClient)
		results = append(results, models.Score{
			Asset: asset,
			Score: score,
		})
	}
	return results
}

// CheckInstance runs all compliance checks on the given instance(SINGLE INSTANCE) and returns the total score
func CheckInstance(instance *ec2.Instance, controls models.NISTControls, iamClient iamiface.IAMAPI,
	ec2Client ec2iface.EC2API, sess *session.Session, cloudTrailClient cloudtrailiface.CloudTrailAPI) int {
	svc := configservice.New(sess)
	score := 110
	for _, control := range controls.Controls {

		result := evaluateCriteria(svc, instance, control.Criteria, iamClient, ec2Client, sess, cloudTrailClient)
		log.Printf("Check: %s, Description: %s, Impact: %d\n", control.Criteria.CheckFunction, control.Criteria.Description, control.Criteria.Value)
		score -= result.Impact
	}

	return score
}

// evaluateCriteria evaluates the criteria for a given instance and returns the compliance result
func evaluateCriteria(svc configserviceiface.ConfigServiceAPI, instance *ec2.Instance, criteria models.Criteria,
	iamClient iamiface.IAMAPI, ec2Client ec2iface.EC2API, sess *session.Session,
	cloudTrailClient cloudtrailiface.CloudTrailAPI) models.ComplianceResult {
	switch criteria.CheckFunction {
	case "CheckSecurityGroup":
		return securitygroup.CheckSecurityGroup(instance, criteria)
	case "CheckIAMRoles":
		return iam.CheckIAMRoles(instance, criteria)
	case "CheckSeparateDuties":
		return iam.CheckSeparateDuties(iamClient, instance, criteria)
	case "CheckLeastPrivilege":
		return iam.CheckLeastPrivilege(iamClient, instance, criteria)
	case "CheckNonPrivilegedAccounts":
		return iam.CheckNonPrivilegedAccounts(iamClient, instance, criteria)
	case "CheckPreventPrivilegedFunctions":
		return iam.CheckPreventPrivilegedFunctions(iamClient, instance, criteria)
	case "CheckRemoteExecutionAuthorization":
		return iam.CheckRemoteExecutionAuthorization(iamClient, instance, criteria)
	case "CheckLogonAttempts":
		return system.CheckLogonAttempts(instance, criteria)
	case "CheckPrivacyNotices":
		return system.CheckPrivacyNotices(instance, criteria)
	case "CheckSessionLock":
		return system.CheckSessionLock(instance, criteria)
	case "CheckSessionTermination":
		return system.CheckSessionTermination(instance, criteria)
	case "CheckRemoteAccessMonitoring":
		return network.CheckRemoteAccessMonitoring(instance, criteria)
	case "CheckRemoteAccessEncryption":
		return network.CheckRemoteAccessEncryption(instance, criteria)
	case "CheckRemoteAccessRouting":
		return network.CheckRemoteAccessRouting(ec2Client, instance, criteria)
	case "CheckFlowLogs":
		return network.CheckFlowLogs(ec2Client, instance, criteria)
	case "CheckWirelessAccessAuthorization":
		return network.CheckWirelessAccessAuthorization(instance, criteria)
	case "CheckWirelessAccessProtection":
		return network.CheckWirelessAccessProtection(instance, criteria)
	case "CheckMobileDeviceConnection":
		return device.CheckMobileDeviceConnection(instance, criteria)
	case "CheckMobileDeviceEncryption":
		return device.CheckMobileDeviceEncryption(instance, criteria)
	case "CheckExternalSystemConnections":
		return device.CheckExternalSystemConnections(instance, criteria)
	case "CheckPortableStorageUse":
		return device.CheckPortableStorageUse(instance, criteria)
	case "CheckPublicCUIControl":
		return device.CheckPublicCUIControl(instance, criteria)
	case "CheckAuditLogs":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditLogs(criteria)
	case "CheckUserTraceability":
		return audit_and_accountability.NewAuditAndAccountability().CheckUserTraceability(criteria)
	case "CheckLoggedEventsReview":
		return audit_and_accountability.NewAuditAndAccountability().CheckLoggedEventsReview(criteria)
	case "CheckAuditLoggingFailure":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditLoggingFailure(criteria)
	case "CheckAuditCorrelation":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditCorrelation(criteria)
	case "CheckAuditReduction":
		return audit_and_accountability.NewAuditAndAccountability().CheckAuditReduction(criteria)
	case "CheckTimeSynchronization":
		return audit_and_accountability.NewAuditAndAccountability().CheckTimeSynchronization(criteria)
	case "CheckSecurityConfiguration":
		return config_management.CheckSecurityConfiguration(svc, criteria)
	case "CheckConfigurationChanges":
		return config_management.CheckConfigurationChanges(svc, criteria)
	case "CheckSecurityImpactAnalysis":
		return config_management.CheckSecurityImpactAnalysis(svc, criteria)
	case "CheckAccessRestrictions":
		return config_management.CheckAccessRestrictions(svc, criteria)
	case "CheckLeastFunctionality":
		return config_management.CheckLeastFunctionality(svc, criteria)
	case "CheckNonessentialFunctions":
		return config_management.CheckNonessentialFunctions(svc, criteria)
	case "CheckSoftwarePolicies":
		return config_management.CheckSoftwarePolicies(svc, criteria)
	case "CheckUserInstalledSoftware":
		return config_management.CheckUserInstalledSoftware(svc, criteria)
	case "CheckBoundaryProtection":
		return protection.CheckBoundaryProtection(sess, criteria)
	case "CheckCryptographicProtection":
		return protection.CheckCryptographicProtection(sess, criteria)
	case "CheckInformationTransmissionProtection":
		return protection.CheckInformationTransmissionProtection(sess, criteria)
	case "CheckSystemUsers":
		return id_auth.CheckSystemUsers(iamClient, cloudTrailClient, ec2Client, criteria)
	case "CheckAuthentication":
		return id_auth.CheckAuthentication(iamClient, criteria)
	case "CheckMFA":
		return id_auth.CheckMFA(iamClient, criteria)
	case "CheckReplayResistantAuthentication":
		return id_auth.CheckReplayResistantAuthentication()
	case "CheckIdentifierReusePrevention":
		return id_auth.CheckIdentifierReusePrevention(iamClient, criteria)
	case "CheckIdentifierDisabling":
		return id_auth.CheckIdentifierDisabling(iamClient, criteria)
	case "CheckPasswordComplexity":
		return id_auth.CheckPasswordComplexity(iamClient, criteria)
	case "CheckPasswordReuseProhibition":
		return id_auth.CheckPasswordReuseProhibition(iamClient, criteria)
	case "CheckTemporaryPasswordUsage":
		return id_auth.CheckTemporaryPasswordUsage(iamClient, criteria)
	case "CheckPasswordEncryption":
		return id_auth.CheckPasswordEncryption(iamClient, criteria)
	case "CheckObscuredFeedback":
		return id_auth.CheckObscuredFeedback(iamClient, criteria)
	case "CheckRiskAssessment":
		return risk_assesment.CheckRiskAssessment(sess, criteria)
	case "CheckVulnerabilityScan":
		return risk_assesment.CheckVulnerabilityScan(sess, criteria)
	case "CheckSecurityAssessmentProcedures":
		return security_assessment.CheckSecurityAssessmentProcedures(sess)
	case "CheckSecurityControlAssessments":
		return security_assessment.CheckSecurityControlAssessments(sess)
	default:
		return models.ComplianceResult{
			Description: criteria.Description,
			Status:      "NO ASSET",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}
}
