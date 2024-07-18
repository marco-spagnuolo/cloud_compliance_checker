package config_management

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
)

// 3.4.1 - Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.
func CheckConfigCompliance() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.DescribeComplianceByConfigRuleInput{}

	result, err := svc.DescribeComplianceByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Check AWS Config compliance",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error describing compliance: %v", err),
			Impact:      5,
		}
	}

	for _, compliance := range result.ComplianceByConfigRules {
		if *compliance.Compliance.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Check AWS Config compliance",
				Status:      "FAIL",
				Response:    "Non-compliant resources found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Check AWS Config compliance",
		Status:      "PASS",
		Response:    "All resources are compliant",
		Impact:      0,
	}
}

// 3.4.2 - Establish and enforce security configuration settings for information technology products employed in organizational systems.
func CheckSecurityConfiguration() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("security-configuration"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure security configurations are applied",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving security configuration compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Ensure security configurations are applied",
				Status:      "FAIL",
				Response:    "Non-compliant security configurations found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure security configurations are applied",
		Status:      "PASS",
		Response:    "All security configurations are compliant",
		Impact:      0,
	}
}

// 3.4.3 - Track, review, approve/disapprove, and audit changes to organizational systems.
func CheckConfigurationChanges() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("configuration-changes"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure configuration changes are tracked and managed",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving configuration change compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Ensure configuration changes are tracked and managed",
				Status:      "FAIL",
				Response:    "Non-compliant configuration changes found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure configuration changes are tracked and managed",
		Status:      "PASS",
		Response:    "All configuration changes are compliant",
		Impact:      0,
	}
}

// 3.4.4 - Analyze the security impact of changes prior to implementation.
func CheckSecurityImpactAnalysis() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("security-impact-analysis"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Analyze the security impact of changes",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving security impact analysis compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Analyze the security impact of changes",
				Status:      "FAIL",
				Response:    "Non-compliant security impact analyses found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Analyze the security impact of changes",
		Status:      "PASS",
		Response:    "All security impact analyses are compliant",
		Impact:      0,
	}
}

// 3.4.5 - Define, document, approve, and enforce physical and logical access restrictions associated with changes to the system.
func CheckAccessRestrictions() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("access-restrictions"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure access restrictions are enforced",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving access restriction compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Ensure access restrictions are enforced",
				Status:      "FAIL",
				Response:    "Non-compliant access restrictions found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure access restrictions are enforced",
		Status:      "PASS",
		Response:    "All access restrictions are compliant",
		Impact:      0,
	}
}

// 3.4.6 - Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.
func CheckLeastFunctionality() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("least-functionality"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure least functionality",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving least functionality compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Ensure least functionality",
				Status:      "FAIL",
				Response:    "Non-compliant least functionality found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure least functionality",
		Status:      "PASS",
		Response:    "All systems comply with least functionality",
		Impact:      0,
	}
}

// 3.4.7 - Restrict, disable, and prevent the use of nonessential programs, functions, ports, protocols, and services.
func CheckNonessentialFunctions() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("nonessential-functions"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Restrict nonessential functions",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving nonessential functions compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Restrict nonessential functions",
				Status:      "FAIL",
				Response:    "Non-compliant nonessential functions found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Restrict nonessential functions",
		Status:      "PASS",
		Response:    "All systems restrict nonessential functions",
		Impact:      0,
	}
}

// 3.4.8 - Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.
func CheckSoftwarePolicies() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("software-policies"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure software policies compliance",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving software policies compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Ensure software policies compliance",
				Status:      "FAIL",
				Response:    "Non-compliant software policies found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure software policies compliance",
		Status:      "PASS",
		Response:    "All systems comply with software policies",
		Impact:      0,
	}
}

// 3.4.9 - Control and monitor user-installed software.
func CheckUserInstalledSoftware() models.ComplianceResult {
	sess := session.Must(session.NewSession())
	svc := configservice.New(sess)

	input := &configservice.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: aws.String("user-installed-software"),
	}

	result, err := svc.GetComplianceDetailsByConfigRule(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Control and monitor user-installed software",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving user-installed software compliance: %v", err),
			Impact:      5,
		}
	}

	for _, evaluationResult := range result.EvaluationResults {
		if *evaluationResult.ComplianceType != "COMPLIANT" {
			return models.ComplianceResult{
				Description: "Control and monitor user-installed software",
				Status:      "FAIL",
				Response:    "Non-compliant user-installed software found",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Control and monitor user-installed software",
		Status:      "PASS",
		Response:    "All systems comply with user-installed software controls",
		Impact:      0,
	}
}
