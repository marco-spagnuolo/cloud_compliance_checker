package main

import (
	"cloud_compliance_checker/compliance"
	"cloud_compliance_checker/config"
	"cloud_compliance_checker/discovery"
	"cloud_compliance_checker/reports"
	"cloud_compliance_checker/scoring"
	"fmt"
)

func main() {
	// Load configuration
	config.LoadConfig()

	// Discover assets
	assets := discovery.DiscoverAssets()

	// Assess assets
	results := compliance.AssessAssets(assets)

	// Calculate scores
	scores := scoring.CalculateScores(results)

	// Generate report
	report := reports.GenerateReport(scores)

	// Output report
	fmt.Println(report)
}
