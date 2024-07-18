package main

import (
	"bufio"
	"cloud_compliance_checker/config"
	"cloud_compliance_checker/discovery"
	"cloud_compliance_checker/internal/checks/evaluation"
	"cloud_compliance_checker/models"
	"cloud_compliance_checker/reports"
	"cloud_compliance_checker/scoring"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
)

func main() {
	// Load configuration
	config.LoadConfig()

	// Load controls from JSON file
	controls, err := loadControls("config/control.json")
	if err != nil {
		log.Fatalf("Failed to load controls: %v", err)
	}

	// Discover assets
	assets := discovery.DiscoverAssets()

	// Create AWS session
	sess := session.Must(session.NewSession())

	// Create IAM, EC2, and CloudTrail clients
	iamClient := iam.New(sess)
	ec2Client := ec2.New(sess)
	cloudTrailClient := cloudtrail.New(sess)

	// Assess assets
	var results []models.AssessmentResult
	for _, asset := range assets {
		result := evaluation.CheckCompliance(asset.Instance, controls, iamClient, ec2Client, cloudTrailClient)
		results = append(results, models.AssessmentResult{
			Asset:         asset,
			Implemented:   result == 110,              // Adjust the logic here based on your requirements
			Planned:       result > 0 && result < 110, // Adjust the logic here based on your requirements
			NotApplicable: result == 0,                // Adjust the logic here based on your requirements
		})
	}

	// Calculate scores
	scores := scoring.CalculateScores(results)

	// Generate report
	report := reports.GenerateReport(scores)

	// Output report
	fmt.Println(report)
}

func loadControls(filePath string) (models.NISTControls, error) {
	var controls models.NISTControls
	file, err := os.Open(filePath)
	if err != nil {
		return controls, err
	}
	data := bufio.NewReader(file)

	decoder := json.NewDecoder(data)
	err = decoder.Decode(&controls)
	if err != nil {
		return controls, err
	}

	return controls, nil
}
