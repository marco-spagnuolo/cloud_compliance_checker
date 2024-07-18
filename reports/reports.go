package reports

import (
	"cloud_compliance_checker/models"
	"fmt"
)

func GenerateReport(scores []models.Score) string {
	report := "Compliance Report\n\n"
	for _, score := range scores {
		report += fmt.Sprintf("Asset: %s\nScore: %d\n\n", score.Asset.Name, score.Score)
	}
	return report
}
