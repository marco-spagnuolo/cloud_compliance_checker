package checks

// import (
// 	"cloud_compliance_checker/internal/check"
// 	"cloud_compliance_checker/internal/utils"

// 	"github.com/aws/aws-sdk-go/service/ec2"
// )

// type ComplianceResult struct {
// 	Description string
// 	Status      string
// 	Response    string
// 	Impact      int
// }

// func evaluateCriteria(instance *ec2.Instance, criteria utils.Criteria) ComplianceResult {
// 	switch criteria.CheckFunction {
// 	case "checkSecurityGroup":
// 		return check.CheckSecurityGroup(instance)
// 	case "checkIAMRoles":
// 		return check.CheckIAMRoles(instance)
// 	default:
// 		return ComplianceResult{
// 			Description: criteria.Description,
// 			Status:      "UNKNOWN",
// 			Response:    "Not Applicable",
// 			Impact:      0,
// 		}
// 	}
// }

// func CheckCompliance(instance *ec2.Instance, controls utils.NISTControls) int {
// 	score := 110
// 	for _, control := range controls.Controls {
// 		for _, criteria := range control.Criteria {
// 			result := evaluateCriteria(instance, criteria)
// 			score -= result.Impact
// 		}
// 	}
// 	return score
// }
