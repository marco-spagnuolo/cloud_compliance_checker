package checks

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
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
				Compliance: &configservice.Compliance{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
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

func TestCheckRiskAssessment(t *testing.T) {
	mockConfig := &mockConfigService{}
	mockSecurityHub := &mockSecurityHub{}

	result := checkRiskAssessmentWithServices(mockConfig, mockSecurityHub)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckVulnerabilityScan(t *testing.T) {
	mockInspector := &mockInspector{}

	result := checkVulnerabilityScanWithService(mockInspector)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckVulnerabilityRemediation(t *testing.T) {
	mockInspector := &mockInspector{}

	result := checkVulnerabilityRemediationWithService(mockInspector)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}
