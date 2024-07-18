package compliance

import (
	"cloud_compliance_checker/internal/checks/access_control/device"
	"cloud_compliance_checker/internal/checks/access_control/iam"
	"cloud_compliance_checker/internal/checks/access_control/network"
	"cloud_compliance_checker/internal/checks/access_control/securitygroup"
	"cloud_compliance_checker/internal/checks/access_control/system"
	"cloud_compliance_checker/internal/utils"
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	awsiam "github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

func AssessAssets(assets []models.Asset) []models.AssessmentResult {
	controls, err := utils.LoadControls("config/controls.json")
	if err != nil {
		fmt.Printf("Error loading controls: %v\n", err)
		return nil
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
	})
	if err != nil {
		fmt.Printf("Error creating AWS session: %v\n", err)
		return nil
	}
	ec2Client := ec2.New(sess)
	iamClient := awsiam.New(sess)

	var results []models.AssessmentResult
	for _, asset := range assets {
		result := AssessAsset(asset, controls, ec2Client, iamClient)
		results = append(results, result)
	}
	return results
}

func AssessAsset(asset models.Asset, controls utils.NISTControls, ec2Client *ec2.EC2, iamClient iamiface.IAMAPI) models.AssessmentResult {
	var complianceResults []models.ComplianceResult
	for _, control := range controls.Controls {
		for _, criteria := range control.Criteria {
			complianceResult := evaluateCriteria(asset, criteria, ec2Client, iamClient)
			complianceResults = append(complianceResults, complianceResult)
		}
	}

	implemented := true
	planned := false
	notApplicable := false
	for _, result := range complianceResults {
		if result.Response == "Planned to be implemented" {
			planned = true
		} else if result.Response == "Not Applicable" {
			notApplicable = true
		} else if result.Response == "FAIL" {
			implemented = false
		}
	}

	return models.AssessmentResult{
		Asset:         asset,
		Implemented:   implemented,
		Planned:       planned,
		NotApplicable: notApplicable,
	}
}

func evaluateCriteria(asset models.Asset, criteria utils.Criteria, ec2Client *ec2.EC2, iamClient iamiface.IAMAPI) models.ComplianceResult {
	switch criteria.CheckFunction {
	case "checkSecurityGroup":
		return securitygroup.CheckSecurityGroup(asset.Instance)
	case "checkIAMRoles":
		return iam.CheckIAMRoles(asset.Instance)
	case "checkFlowLogs":
		return network.CheckFlowLogs(ec2Client, asset.Instance)
	case "checkSeparateDuties":
		return iam.CheckSeparateDuties(iamClient, asset.Instance)
	case "checkLeastPrivilege":
		return iam.CheckLeastPrivilege(iamClient, asset.Instance)
	case "checkNonPrivilegedAccounts":
		return iam.CheckNonPrivilegedAccounts(iamClient, asset.Instance)
	case "checkPreventPrivilegedFunctions":
		return iam.CheckPreventPrivilegedFunctions(iamClient, asset.Instance)
	case "checkLogonAttempts":
		return system.CheckLogonAttempts(asset.Instance)
	case "checkPrivacyNotices":
		return system.CheckPrivacyNotices(asset.Instance)
	case "checkSessionLock":
		return system.CheckSessionLock(asset.Instance)
	case "checkSessionTermination":
		return system.CheckSessionTermination(asset.Instance)
	case "checkRemoteAccessMonitoring":
		return network.CheckRemoteAccessMonitoring(asset.Instance)
	case "checkRemoteAccessEncryption":
		return network.CheckRemoteAccessEncryption(asset.Instance)
	case "checkRemoteAccessRouting":
		return network.CheckRemoteAccessRouting(ec2Client, asset.Instance)
	case "checkRemoteExecutionAuthorization":
		return iam.CheckRemoteExecutionAuthorization(iamClient, asset.Instance)
	case "checkWirelessAccessAuthorization":
		return network.CheckWirelessAccessAuthorization(asset.Instance)
	case "checkWirelessAccessProtection":
		return network.CheckWirelessAccessProtection(asset.Instance)
	case "checkMobileDeviceConnection":
		return device.CheckMobileDeviceConnection(asset.Instance)
	case "checkMobileDeviceEncryption":
		return device.CheckMobileDeviceEncryption(asset.Instance)
	case "checkExternalSystemConnections":
		return device.CheckExternalSystemConnections(asset.Instance)
	case "checkPortableStorageUse":
		return device.CheckPortableStorageUse(asset.Instance)
	case "checkPublicCUIControl":
		return device.CheckPublicCUIControl(asset.Instance)
	default:
		return models.ComplianceResult{
			Description: criteria.Description,
			Status:      "UNKNOWN",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}
}
