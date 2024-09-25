package evaluation

import (
	"cloud_compliance_checker/internal/checks/access_control/policy"
	"cloud_compliance_checker/models"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

// EvaluateAssets evaluates all assets and returns the compliance results
func EvaluateAssets(assets []models.Asset, controls models.NISTControls,
	cfg aws.Config, cloudTrailClient *cloudtrail.Client) []models.Score {
	var results []models.Score
	for _, asset := range assets {
		score := CheckInstance(controls, cfg, cloudTrailClient)
		results = append(results, models.Score{
			Asset: asset,
			Score: score,
		})
	}
	return results
}

// CheckInstance runs all compliance checks on the given instance (SINGLE INSTANCE) and returns the total score
func CheckInstance(controls models.NISTControls, cfg aws.Config, cloudTrailClient *cloudtrail.Client) int {

	svc := configservice.NewFromConfig(cfg)
	score := 110
	for _, control := range controls.Controls {
		for _, criteria := range control.Criteria {
			result := evaluateCriteria(svc, criteria, cfg, cloudTrailClient)
			log.Printf("Check: %s, Description: %s, Impact: %d\n", criteria.CheckFunction, criteria.Description, criteria.Value)
			score -= result.Impact
		}
	}

	return score
}

// evaluateCriteria evaluates the criteria for a given instance and returns the compliance result
func evaluateCriteria(svc *configservice.Client, criteria models.Criteria,
	cfg aws.Config, cloudTrailClient *cloudtrail.Client) models.ComplianceResult {
	switch criteria.CheckFunction {
	case "CheckSecurityGroup":
		check := policy.NewIAMCheck(cfg)
		err := check.Run()
		if err != nil {
			log.Printf("Error running IAM check: %v", err)
			return models.ComplianceResult{
				Description: criteria.Description,
				Status:      "ERROR",
				Response:    err.Error(),
				Impact:      0,
			}
		}
		return models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      criteria.Value,
		}

	default:
		return models.ComplianceResult{
			Description: criteria.Description,
			Status:      "NO ASSET",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}
}
