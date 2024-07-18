package scoring

import (
	"cloud_compliance_checker/models"
)

func CalculateScores(results []models.AssessmentResult) []models.Score {
	var scores []models.Score
	baseScore := 110

	for _, result := range results {
		score := models.Score{
			Asset: result.Asset,
			Score: baseScore,
		}

		if !result.Implemented {
			score.Score -= 5 // Example deduction
		}
		if result.Planned {
			score.Score -= 5 // Example deduction
		}
		if result.NotApplicable {
			score.Score -= 0 // No deduction
		}

		scores = append(scores, score)
	}
	return scores
}
