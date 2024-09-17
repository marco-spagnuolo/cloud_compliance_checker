package compliance

// import (
// 	"cloud_compliance_checker/internal/utils"
// 	"cloud_compliance_checker/models"
// 	"fmt"

// 	"github.com/aws/aws-sdk-go/aws"
// 	"github.com/aws/aws-sdk-go/aws/session"
// 	"github.com/aws/aws-sdk-go/service/ec2"
// 	awsiam "github.com/aws/aws-sdk-go/service/iam"
// 	"github.com/aws/aws-sdk-go/service/iam/iamiface"
// )

// func AssessAssets(assets []models.Asset) []models.AssessmentResult {
// 	controls, err := utils.LoadControls("config/controls.json")
// 	if err != nil {
// 		fmt.Printf("Error loading controls: %v\n", err)
// 		return nil
// 	}

// 	sess, err := session.NewSession(&aws.Config{
// 		Region: aws.String("us-west-2"),
// 	})
// 	if err != nil {
// 		fmt.Printf("Error creating AWS session: %v\n", err)
// 		return nil
// 	}
// 	ec2Client := ec2.New(sess)
// 	iamClient := awsiam.New(sess)

// 	var results []models.AssessmentResult
// 	for _, asset := range assets {
// 		result := AssessAsset(asset, controls, ec2Client, iamClient)
// 		results = append(results, result)
// 	}
// 	return results
// }

// func AssessAsset(asset models.Asset, controls utils.NISTControls, ec2Client *ec2.EC2, iamClient iamiface.IAMAPI) models.AssessmentResult {
// 	var complianceResults []models.ComplianceResult
// 	for _, control := range controls.Controls {
// 		for _, criteria := range control.Criteria {
// 			complianceResult := evaluateCriteria(asset, criteria, ec2Client, iamClient)
// 			complianceResults = append(complianceResults, complianceResult)
// 		}
// 	}

// 	implemented := true
// 	planned := false
// 	notApplicable := false
// 	for _, result := range complianceResults {
// 		if result.Response == "Planned to be implemented" {
// 			planned = true
// 		} else if result.Response == "Not Applicable" {
// 			notApplicable = true
// 		} else if result.Response == "FAIL" {
// 			implemented = false
// 		}
// 	}

// 	return models.AssessmentResult{
// 		Asset:         asset,
// 		Implemented:   implemented,
// 		Planned:       planned,
// 		NotApplicable: notApplicable,
// 	}
// }
