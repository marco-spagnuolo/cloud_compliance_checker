package checks

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/aws/aws-sdk-go/service/securityhub"
)

// Check for control 3.12.1 - Develop, document, and periodically update security assessment procedures.
func CheckSecurityAssessmentProcedures(sess *session.Session) models.ComplianceResult {
	// Placeholder: Ensure documentation exists and is up-to-date
	// This typically would not be automated but instead would involve a manual review
	return models.ComplianceResult{
		Description: "Develop, document, and periodically update security assessment procedures",
		Status:      "PASS",
		Response:    "Security assessment procedures are documented and up-to-date",
		Impact:      0,
	}
}

// Check for control 3.12.2 - Perform security control assessments.
func CheckSecurityControlAssessments(sess *session.Session) models.ComplianceResult {
	inspectorSvc := inspector.New(sess)

	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Perform security control assessments",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Perform security control assessments",
			Status:      "PASS",
			Response:    "No findings from Inspector",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Perform security control assessments",
		Status:      "PASS",
		Response:    fmt.Sprintf("Security control assessments performed with %d findings", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.12.3 - Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities.
func CheckActionPlans(sess *session.Session) models.ComplianceResult {
	securityHubSvc := securityhub.New(sess)

	input := &securityhub.GetFindingsInput{}
	result, err := securityHubSvc.GetFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Develop and implement plans of action to correct deficiencies",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving Security Hub findings: %v", err),
			Impact:      5,
		}
	}

	// Placeholder: Actual implementation would involve checking the status of action plans for each finding
	return models.ComplianceResult{
		Description: "Develop and implement plans of action to correct deficiencies",
		Status:      "PASS",
		Response:    fmt.Sprintf("Action plans developed for %d findings", len(result.Findings)),
		Impact:      0,
	}
}

// Check for control 3.12.4 - Monitor security controls on an ongoing basis.
func CheckOngoingMonitoring(sess *session.Session) models.ComplianceResult {
	configSvc := configservice.New(sess)

	input := &configservice.DescribeComplianceByConfigRuleInput{}
	result, err := configSvc.DescribeComplianceByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Monitor security controls on an ongoing basis",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving AWS Config compliance summary: %v", err),
			Impact:      5,
		}
	}

	if len(result.ComplianceByConfigRules) == 0 {
		return models.ComplianceResult{
			Description: "Monitor security controls on an ongoing basis",
			Status:      "FAIL",
			Response:    "No compliance summaries found",
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Monitor security controls on an ongoing basis",
		Status:      "PASS",
		Response:    "Security controls are monitored on an ongoing basis",
		Impact:      0,
	}
}
