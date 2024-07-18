package config_management

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
)

// CheckConfigCompliance checks the compliance status of AWS resources using AWS Config
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
