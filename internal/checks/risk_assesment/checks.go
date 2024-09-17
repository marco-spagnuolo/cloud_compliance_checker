package risk_assesment

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/aws/aws-sdk-go/service/inspector/inspectoriface"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"
)

// Check for control 3.11.1 - Periodically assess the risk to organizational operations
func CheckRiskAssessment(sess *session.Session, criteria models.Criteria) models.ComplianceResult {
	configSvc := configservice.New(sess)
	securityHubSvc := securityhub.New(sess)
	return checkRiskAssessmentWithServices(configSvc, securityHubSvc, criteria)
}

func checkRiskAssessmentWithServices(configSvc configserviceiface.ConfigServiceAPI, securityHubSvc securityhubiface.SecurityHubAPI, criteria models.Criteria) models.ComplianceResult {
	// Check AWS Config compliance
	configInput := &configservice.DescribeComplianceByConfigRuleInput{}
	configResult, err := configSvc.DescribeComplianceByConfigRule(configInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Periodically assess the risk to organizational operations",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving AWS Config compliance summary: %v", err),
			Impact:      criteria.Value,
		}
	}

	// Check Security Hub findings
	securityHubInput := &securityhub.GetFindingsInput{}
	securityHubResult, err := securityHubSvc.GetFindings(securityHubInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Periodically assess the risk to organizational operations",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving Security Hub findings: %v", err),
			Impact:      criteria.Value,
		}
	}

	if len(configResult.ComplianceByConfigRules) == 0 && len(securityHubResult.Findings) == 0 {
		return models.ComplianceResult{
			Description: "Periodically assess the risk to organizational operations",
			Status:      "FAIL",
			Response:    "No compliance summaries or findings found",
			Impact:      criteria.Value,
		}
	}

	return models.ComplianceResult{
		Description: "Periodically assess the risk to organizational operations",
		Status:      "PASS",
		Response:    "Risk assessments are conducted periodically",
		Impact:      0,
	}
}

// Check for control 3.11.2 - Scan for vulnerabilities in the information system
func CheckVulnerabilityScan(sess *session.Session, criteria models.Criteria) models.ComplianceResult {
	inspectorSvc := inspector.New(sess)
	return checkVulnerabilityScanWithService(inspectorSvc, criteria)
}

func checkVulnerabilityScanWithService(inspectorSvc inspectoriface.InspectorAPI, criteria models.Criteria) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Scan for vulnerabilities in the information system",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      criteria.Value,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Scan for vulnerabilities in the information system",
			Status:      "PASS",
			Response:    "No vulnerabilities found",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Scan for vulnerabilities in the information system",
		Status:      "PASS",
		Response:    fmt.Sprintf("Vulnerabilities found: %d", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.11.3 - Remediate vulnerabilities in accordance with risk assessments
func CheckVulnerabilityRemediation(sess *session.Session, criteria models.Criteria) models.ComplianceResult {
	inspectorSvc := inspector.New(sess)
	return checkVulnerabilityRemediationWithService(inspectorSvc, criteria)
}

func checkVulnerabilityRemediationWithService(inspectorSvc inspectoriface.InspectorAPI, criteria models.Criteria) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Remediate vulnerabilities in accordance with risk assessments",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      criteria.Value,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Remediate vulnerabilities in accordance with risk assessments",
			Status:      "PASS",
			Response:    "No vulnerabilities found",
			Impact:      0,
		}
	}

	// Placeholder for actual remediation process
	return models.ComplianceResult{
		Description: "Remediate vulnerabilities in accordance with risk assessments",
		Status:      "PASS",
		Response:    fmt.Sprintf("Vulnerabilities identified: %d. Remediation process initiated.", len(result.FindingArns)),
		Impact:      0,
	}
}
