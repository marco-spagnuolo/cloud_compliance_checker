package main

import (
	"bufio"
	"cloud_compliance_checker/config"
	"cloud_compliance_checker/discovery"
	"cloud_compliance_checker/internal/checks/evaluation"
	"cloud_compliance_checker/models"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
)

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

	// Evaluate assets
	results := evaluation.EvaluateAssets(assets, controls, iamClient, ec2Client, sess, cloudTrailClient)

	// Print results
	for _, result := range results {
		fmt.Printf("Asset: %s\n", result.Asset.Name)
		fmt.Printf("Compliance Score: %d\n", result.Score)
		fmt.Println()
	}
}
