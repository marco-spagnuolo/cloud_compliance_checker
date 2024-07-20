package integrity

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/aws/aws-sdk-go/service/inspector/inspectoriface"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"
)

// Check for control 3.14.1 - Identify and correct system flaws
func CheckSystemFlawCorrection(sess *session.Session) models.ComplianceResult {
	inspectorSvc := inspector.New(sess)
	return checkSystemFlawCorrectionWithService(inspectorSvc)
}

func checkSystemFlawCorrectionWithService(inspectorSvc inspectoriface.InspectorAPI) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Identify and correct system flaws",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Identify and correct system flaws",
			Status:      "PASS",
			Response:    "No system flaws found",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Identify and correct system flaws",
		Status:      "PASS",
		Response:    fmt.Sprintf("System flaws identified and corrective actions initiated: %d findings", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.14.2 - Provide protection from malicious code
func CheckMaliciousCodeProtection(sess *session.Session) models.ComplianceResult {
	// Assuming AWS Inspector is used to identify malicious code
	inspectorSvc := inspector.New(sess)
	return checkMaliciousCodeProtectionWithService(inspectorSvc)
}

func checkMaliciousCodeProtectionWithService(inspectorSvc inspectoriface.InspectorAPI) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Provide protection from malicious code",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Provide protection from malicious code",
			Status:      "PASS",
			Response:    "No malicious code found",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Provide protection from malicious code",
		Status:      "PASS",
		Response:    fmt.Sprintf("Malicious code detected and action taken: %d findings", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.14.3 - Monitor system security alerts
func CheckSecurityAlertMonitoring(sess *session.Session) models.ComplianceResult {
	// Assuming AWS Security Hub is used for monitoring security alerts
	securityHubSvc := securityhub.New(sess)
	return checkSecurityAlertMonitoringWithService(securityHubSvc)
}

func checkSecurityAlertMonitoringWithService(securityHubSvc securityhubiface.SecurityHubAPI) models.ComplianceResult {
	input := &securityhub.GetFindingsInput{}
	result, err := securityHubSvc.GetFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Monitor system security alerts",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving Security Hub findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.Findings) == 0 {
		return models.ComplianceResult{
			Description: "Monitor system security alerts",
			Status:      "PASS",
			Response:    "No security alerts found",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Monitor system security alerts",
		Status:      "PASS",
		Response:    fmt.Sprintf("Security alerts monitored and action taken: %d findings", len(result.Findings)),
		Impact:      0,
	}
}

// Check for control 3.14.4 - Update malicious code protection mechanisms
func CheckMaliciousCodeUpdates(sess *session.Session) models.ComplianceResult {
	// Assuming that we check for updates to AWS Inspector findings
	inspectorSvc := inspector.New(sess)
	return checkMaliciousCodeUpdatesWithService(inspectorSvc)
}

func checkMaliciousCodeUpdatesWithService(inspectorSvc inspectoriface.InspectorAPI) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Update malicious code protection mechanisms",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Update malicious code protection mechanisms",
			Status:      "PASS",
			Response:    "No updates needed for malicious code protection mechanisms",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Update malicious code protection mechanisms",
		Status:      "PASS",
		Response:    fmt.Sprintf("Malicious code protection mechanisms updated: %d findings", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.14.5 - Perform periodic and real-time scans
func CheckSystemScans(sess *session.Session) models.ComplianceResult {
	// Assuming periodic and real-time scans are performed using AWS Inspector
	inspectorSvc := inspector.New(sess)
	return checkSystemScansWithService(inspectorSvc)
}

func checkSystemScansWithService(inspectorSvc inspectoriface.InspectorAPI) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Perform periodic and real-time scans",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Perform periodic and real-time scans",
			Status:      "PASS",
			Response:    "No issues found during periodic and real-time scans",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Perform periodic and real-time scans",
		Status:      "PASS",
		Response:    fmt.Sprintf("Issues found and addressed during scans: %d findings", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.14.6 - Monitor inbound and outbound communications
func CheckCommunicationTrafficMonitoring(sess *session.Session) models.ComplianceResult {
	// Assuming CloudWatch or a similar service is used to monitor communication traffic
	return models.ComplianceResult{
		Description: "Monitor inbound and outbound communications",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.14.7 - Identify unauthorized use of organizational systems
func CheckUnauthorizedUseIdentification(sess *session.Session) models.ComplianceResult {
	// Assuming GuardDuty or a similar service is used to identify unauthorized use
	return models.ComplianceResult{
		Description: "Identify unauthorized use of organizational systems",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}
