package security_assessment

import (
	"cloud_compliance_checker/models"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/aws/aws-sdk-go/service/inspector/inspectoriface"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"
)

// Mock ConfigService
type mockConfigService struct {
	configserviceiface.ConfigServiceAPI
}

func (m *mockConfigService) DescribeComplianceByConfigRule(input *configservice.DescribeComplianceByConfigRuleInput) (*configservice.DescribeComplianceByConfigRuleOutput, error) {
	return &configservice.DescribeComplianceByConfigRuleOutput{
		ComplianceByConfigRules: []*configservice.ComplianceByConfigRule{
			{
				ConfigRuleName: aws.String("test-rule"),
				Compliance: &configservice.Compliance{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
	}, nil
}

// Mock Inspector
type mockInspector struct {
	inspectoriface.InspectorAPI
}

func (m *mockInspector) ListFindings(input *inspector.ListFindingsInput) (*inspector.ListFindingsOutput, error) {
	return &inspector.ListFindingsOutput{
		FindingArns: []*string{
			aws.String("arn:aws:inspector:us-west-2:123456789012:target/0-0kFIPusq/template/0-WEcNVbq7/run/0-0abcxE01/finding/0-0rL3c6Y1"),
		},
	}, nil
}

// Mock SecurityHub
type mockSecurityHub struct {
	securityhubiface.SecurityHubAPI
}

func (m *mockSecurityHub) GetFindings(input *securityhub.GetFindingsInput) (*securityhub.GetFindingsOutput, error) {
	return &securityhub.GetFindingsOutput{
		Findings: []*securityhub.AwsSecurityFinding{
			{
				Description: aws.String("Test finding"),
			},
		},
	}, nil
}

func TestCheckSecurityAssessmentProcedures(t *testing.T) {
	result := CheckSecurityAssessmentProcedures(&session.Session{})
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckSecurityControlAssessments(t *testing.T) {
	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials("test", "test", ""),
	}))
	mockInspector := &mockInspector{}

	result := CheckSecurityControlAssessmentsWithService(sess, mockInspector)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func CheckSecurityControlAssessmentsWithService(sess *session.Session, inspectorSvc inspectoriface.InspectorAPI) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Perform security control assessments",
			Status:      "FAIL",
			Response:    "Error listing Inspector findings",
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
		Response:    "Security control assessments performed",
		Impact:      0,
	}
}

func TestCheckActionPlans(t *testing.T) {
	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials("test", "test", ""),
	}))
	mockSecurityHub := &mockSecurityHub{}

	result := CheckActionPlansWithService(sess, mockSecurityHub)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func CheckActionPlansWithService(sess *session.Session, securityHubSvc securityhubiface.SecurityHubAPI) models.ComplianceResult {
	input := &securityhub.GetFindingsInput{}
	_, err := securityHubSvc.GetFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Develop and implement plans of action to correct deficiencies",
			Status:      "FAIL",
			Response:    "Error retrieving Security Hub findings",
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Develop and implement plans of action to correct deficiencies",
		Status:      "PASS",
		Response:    "Action plans developed",
		Impact:      0,
	}
}

func TestCheckOngoingMonitoring(t *testing.T) {
	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials("test", "test", ""),
	}))
	mockConfig := &mockConfigService{}

	result := CheckOngoingMonitoringWithService(sess, mockConfig)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func CheckOngoingMonitoringWithService(sess *session.Session, configSvc configserviceiface.ConfigServiceAPI) models.ComplianceResult {
	input := &configservice.DescribeComplianceByConfigRuleInput{}
	result, err := configSvc.DescribeComplianceByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Monitor security controls on an ongoing basis",
			Status:      "FAIL",
			Response:    "Error retrieving AWS Config compliance summary",
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
