package assessment

import (
	"cloud_compliance_checker/internal/checks"
	"cloud_compliance_checker/internal/utils"
	"cloud_compliance_checker/models"
	"fmt"
)

func AssessAssets(assets []models.Asset) []models.AssessmentResult {
	controls, err := utils.LoadControls("config/controls.json")
	if err != nil {
		fmt.Printf("Error loading controls: %v\n", err)
		return nil
	}

	var results []models.AssessmentResult
	for _, asset := range assets {
		result := AssessAsset(asset, controls)
		results = append(results, result)
	}
	return results
}

func AssessAsset(asset models.Asset, controls utils.NISTControls) models.AssessmentResult {
	var complianceResults []models.ComplianceResult
	for _, control := range controls.Controls {
		for _, criteria := range control.Criteria {
			complianceResult := evaluateCriteria(asset, criteria)
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

func evaluateCriteria(asset models.Asset, criteria utils.Criteria) models.ComplianceResult {
	switch criteria.CheckFunction {
	case "checkSecurityGroup":
		return checks.CheckSecurityGroup(asset.Instance)
	case "checkIAMRoles":
		return checks.CheckIAMRoles(asset.Instance)
	case "checkFlowLogs":
		return checks.CheckFlowLogs(asset.Instance)
	case "checkSeparateDuties":
		return checks.CheckSeparateDuties(asset.Instance)
	case "checkLeastPrivilege":
		return checks.CheckLeastPrivilege(asset.Instance)
	case "checkNonPrivilegedAccounts":
		return checks.CheckNonPrivilegedAccounts(asset.Instance)
	case "checkPreventPrivilegedFunctions":
		return checks.CheckPreventPrivilegedFunctions(asset.Instance)
	case "checkLogonAttempts":
		return checks.CheckLogonAttempts(asset.Instance)
	case "checkPrivacyNotices":
		return checks.CheckPrivacyNotices(asset.Instance)
	case "checkSessionLock":
		return checks.CheckSessionLock(asset.Instance)
	case "checkSessionTermination":
		return checks.CheckSessionTermination(asset.Instance)
	case "checkRemoteAccessMonitoring":
		return checks.CheckRemoteAccessMonitoring(asset.Instance)
	case "checkRemoteAccessEncryption":
		return checks.CheckRemoteAccessEncryption(asset.Instance)
	case "checkRemoteAccessRouting":
		return checks.CheckRemoteAccessRouting(asset.Instance)
	case "checkRemoteExecutionAuthorization":
		return checks.CheckRemoteExecutionAuthorization(asset.Instance)
	case "checkWirelessAccessAuthorization":
		return checks.CheckWirelessAccessAuthorization(asset.Instance)
	case "checkWirelessAccessProtection":
		return checks.CheckWirelessAccessProtection(asset.Instance)
	case "checkMobileDeviceConnection":
		return checks.CheckMobileDeviceConnection(asset.Instance)
	case "checkMobileDeviceEncryption":
		return checks.CheckMobileDeviceEncryption(asset.Instance)
	case "checkExternalSystemConnections":
		return checks.CheckExternalSystemConnections(asset.Instance)
	case "checkPortableStorageUse":
		return checks.CheckPortableStorageUse(asset.Instance)
	case "checkPublicCUIControl":
		return checks.CheckPublicCUIControl(asset.Instance)
	default:
		return models.ComplianceResult{
			Description: criteria.Description,
			Status:      "UNKNOWN",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}
}
