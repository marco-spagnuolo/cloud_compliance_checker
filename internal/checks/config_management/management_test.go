package config_management

import (
	"cloud_compliance_checker/models"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
)

// Mock implementation of the ConfigServiceAPI interface
type mockConfigServiceClient struct {
	configserviceiface.ConfigServiceAPI
	response *configservice.GetComplianceDetailsByConfigRuleOutput
	err      error
}

func (m *mockConfigServiceClient) DescribeComplianceByConfigRule(input *configservice.DescribeComplianceByConfigRuleInput) (*configservice.DescribeComplianceByConfigRuleOutput, error) {
	return &configservice.DescribeComplianceByConfigRuleOutput{
		ComplianceByConfigRules: []*configservice.ComplianceByConfigRule{
			{
				ConfigRuleName: aws.String("config-rule"),
				Compliance: &configservice.Compliance{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
	}, nil
}

func (m *mockConfigServiceClient) GetComplianceDetailsByConfigRule(input *configservice.GetComplianceDetailsByConfigRuleInput) (*configservice.GetComplianceDetailsByConfigRuleOutput, error) {
	return m.response, m.err
}

func TestCheckConfigCompliance(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckConfigCompliance(mockSvc)
	expected := models.ComplianceResult{
		Description: "Check AWS Config compliance",
		Status:      "PASS",
		Response:    "All resources are compliant",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckSecurityConfiguration(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckSecurityConfiguration(mockSvc)
	expected := models.ComplianceResult{
		Description: "Ensure security configurations are applied",
		Status:      "PASS",
		Response:    "All security configurations are compliant",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckConfigurationChanges(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckConfigurationChanges(mockSvc)
	expected := models.ComplianceResult{
		Description: "Ensure configuration changes are tracked and managed",
		Status:      "PASS",
		Response:    "All configuration changes are compliant",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckSecurityImpactAnalysis(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckSecurityImpactAnalysis(mockSvc)
	expected := models.ComplianceResult{
		Description: "Analyze the security impact of changes",
		Status:      "PASS",
		Response:    "All security impact analyses are compliant",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckAccessRestrictions(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckAccessRestrictions(mockSvc)
	expected := models.ComplianceResult{
		Description: "Ensure access restrictions are enforced",
		Status:      "PASS",
		Response:    "All access restrictions are compliant",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckLeastFunctionality(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckLeastFunctionality(mockSvc)
	expected := models.ComplianceResult{
		Description: "Ensure least functionality",
		Status:      "PASS",
		Response:    "All systems comply with least functionality",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckNonessentialFunctions(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckNonessentialFunctions(mockSvc)
	expected := models.ComplianceResult{
		Description: "Restrict nonessential functions",
		Status:      "PASS",
		Response:    "All systems restrict nonessential functions",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckSoftwarePolicies(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckSoftwarePolicies(mockSvc)
	expected := models.ComplianceResult{
		Description: "Ensure software policies compliance",
		Status:      "PASS",
		Response:    "All systems comply with software policies",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestCheckUserInstalledSoftware(t *testing.T) {
	mockSvc := &mockConfigServiceClient{
		response: &configservice.GetComplianceDetailsByConfigRuleOutput{
			EvaluationResults: []*configservice.EvaluationResult{
				{
					ComplianceType: aws.String("COMPLIANT"),
				},
			},
		},
		err: nil,
	}

	result := CheckUserInstalledSoftware(mockSvc)
	expected := models.ComplianceResult{
		Description: "Control and monitor user-installed software",
		Status:      "PASS",
		Response:    "All systems comply with user-installed software controls",
		Impact:      0,
	}

	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}
