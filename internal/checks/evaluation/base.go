package evaluation

import (
	policy "cloud_compliance_checker/internal/checks/access_control/iampolicy"
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

// EvaluateAssets evaluates all assets and returns the compliance results
func EvaluateAssets(assets []models.Asset, controls models.NISTControls,
	cfg aws.Config, cloudTrailClient *cloudtrail.Client) []models.Score {
	var results []models.Score

	// Separator for readability
	fmt.Println("===== Compliance Evaluation Results =====")

	for _, asset := range assets {
		fmt.Printf("\nAsset: %s\n", asset.Name)
		fmt.Println("======================================")

		score := CheckInstance(controls, cfg, cloudTrailClient)
		results = append(results, models.Score{
			Asset: asset,
			Score: score,
		})

		// Display compliance score for the asset
		fmt.Printf("Compliance Score for Asset %s: %d\n", asset.Name, score)
		fmt.Println("--------------------------------------")
	}

	return results
}

// CheckInstance runs all compliance checks on the given instance (SINGLE INSTANCE) and returns the total score
func CheckInstance(controls models.NISTControls, cfg aws.Config, cloudTrailClient *cloudtrail.Client) int {
	svc := configservice.NewFromConfig(cfg)
	score := 110

	for _, control := range controls.Controls {
		fmt.Printf("\n*Control: %s - %s\n", control.ID, control.Description)

		for _, criteria := range control.Criteria {
			result := evaluateCriteria(svc, criteria, cfg, cloudTrailClient)

			// Print results for each check in a readable format
			fmt.Printf("  Check: %s\n", criteria.CheckFunction)
			fmt.Printf("    Description: %s\n", criteria.Description)
			fmt.Printf("    Result: %s\n", result.Status)
			fmt.Printf("    Impact: %d\n", criteria.Value)

			score -= result.Impact
		}
	}

	return score
}

// evaluateCriteria evaluates the criteria for a given instance and returns the compliance result
func evaluateCriteria(svc *configservice.Client, criteria models.Criteria,
	cfg aws.Config, cloudTrailClient *cloudtrail.Client) models.ComplianceResult {
	var result models.ComplianceResult
	check := policy.NewIAMCheck(cfg)

	switch criteria.CheckFunction {
	case "CheckUsersPolicies":
		err := check.RunCheckPolicies()
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			return result
		}
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
		}

	case "CheckAcceptedPolicies":
		err := check.RunCheckAcceptedPolicies()
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			return result
		}
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      0,
		}

	case "CheckCUIFlow":
		err := check.RunCheckCUIFlow()
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			return result
		}
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      0,
		}
	case "CheckSeparateDuties":
		err := check.RunCheckSeparateDuties()
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			return result
		}
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      0,
		}
	case "CheckLeastPrivilege":
		err := check.RunPrivilegeCheck()
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			return result
		}
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      0,
		}
	case "CheckPrivilegedAccounts":
		err := check.RunPrivilegeAccountCheck()
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			return result
		}
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      0,
		}

	default:
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "NO ASSET",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}

	return result
}
