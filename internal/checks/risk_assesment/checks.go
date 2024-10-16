package risk_assesment

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
)

/*
AWS Inspector can be considered a tool for risk assessment, particularly in the context of security and
vulnerability management. It automatically assesses applications for vulnerabilities and deviations from best practices.
By scanning for software vulnerabilities, security misconfigurations, and unintended network exposure,
AWS Inspector helps identify risks associated with system configurations, software versions, and network setups.

In the context of NIST SP 800-171, this helps fulfill requirements to assess risks by identifying
potential threats and vulnerabilities, which are crucial for protecting CUI
*/
// CheckLastAssessmentRun retrieves the latest completed assessment run for a given template
func CheckLastAssessmentRun(templateArn string, awsCfg aws.Config) (time.Time, error) {
	log.Printf("Fetching last assessment run for template: %s", templateArn)
	svc := inspector.NewFromConfig(awsCfg)

	// Use Inspector1 to list assessment runs
	input := &inspector.ListAssessmentRunsInput{
		AssessmentTemplateArns: []string{templateArn},
		MaxResults:             aws.Int32(5), // Limit to 5 recent runs
	}

	resp, err := svc.ListAssessmentRuns(context.TODO(), input)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to fetch last assessment run: %v", err)
	}

	if len(resp.AssessmentRunArns) == 0 {
		log.Println("No previous assessment runs found")
		return time.Time{}, fmt.Errorf("no previous assessment runs found")
	}

	// Log details of previous assessment runs
	log.Println("Previous assessment runs:")
	var lastCompletedRun time.Time
	for _, runArn := range resp.AssessmentRunArns {
		runDetails, err := svc.DescribeAssessmentRuns(context.TODO(), &inspector.DescribeAssessmentRunsInput{
			AssessmentRunArns: []string{runArn},
		})
		if err != nil {
			log.Printf("Failed to describe assessment run %s: %v", runArn, err)
			continue
		}

		for _, run := range runDetails.AssessmentRuns {
			log.Printf("Run Name: %s, ARN: %s, Completed At: %v", *run.Name, *run.Arn, run.CompletedAt)
			if run.CompletedAt != nil && (lastCompletedRun.IsZero() || run.CompletedAt.After(lastCompletedRun)) {
				lastCompletedRun = *run.CompletedAt
			}
		}
	}

	if lastCompletedRun.IsZero() {
		return time.Time{}, fmt.Errorf("no completed assessment runs found")
	}

	log.Printf("Last assessment run was completed at: %s", lastCompletedRun)
	return lastCompletedRun, nil
}

// ScheduleRiskAssessment performs automated risk checks
// 03.11.1
func ScheduleRiskAssessment(awsCfg aws.Config) error {
	log.Printf("Initiating risk assessment - Frequency: %s", config.AppConfig.AWS.RiskAssessmentConfig.Frequency)

	// Get the last run time using Inspector APIs
	lastRun, err := CheckLastAssessmentRun(config.AppConfig.AWS.RiskAssessmentConfig.Arn, awsCfg)
	if err != nil {
		log.Printf("No previous assessment runs found: %v. Starting an initial assessment.", err)

		// Conduct an initial vulnerability scan using AWS Inspector
		svc := inspector.NewFromConfig(awsCfg)
		input := &inspector.StartAssessmentRunInput{
			AssessmentTemplateArn: aws.String(config.AppConfig.AWS.RiskAssessmentConfig.Arn),
		}

		_, err := svc.StartAssessmentRun(context.TODO(), input)
		if err != nil {
			log.Printf("Error starting initial risk assessment scan: %v", err)
			return err
		}

		log.Println("Initial risk assessment started successfully.")
		return nil
	}

	// Proceed with normal scheduling logic
	requiredDuration := getFrequencyDuration(config.AppConfig.AWS.RiskAssessmentConfig.Frequency)
	actualDuration := time.Since(lastRun)

	log.Printf("Time since last run: %v, Required frequency duration: %v", actualDuration, requiredDuration)
	if actualDuration >= requiredDuration {
		svc := inspector.NewFromConfig(awsCfg)
		input := &inspector.StartAssessmentRunInput{
			AssessmentTemplateArn: aws.String(config.AppConfig.AWS.RiskAssessmentConfig.Arn),
		}

		_, err := svc.StartAssessmentRun(context.TODO(), input)
		if err != nil {
			log.Printf("Error starting risk assessment scan: %v", err)
			return err
		}

		log.Println("Risk assessment started successfully.")
	} else {
		log.Printf("Skipping assessment; the last run was %v ago, and the frequency requirement is %v.", actualDuration, requiredDuration)
	}
	// // Simulate checking supply chain vendors' compliance
	// for _, vendor := range config.AppConfig.AWS.RiskAssessmentConfig.SupplyChainVendors {
	// 	compliant := SimulateVendorCompliance(vendor)
	// 	if !compliant {
	// 		log.Printf("Vendor %s failed compliance check!", vendor)
	// 	}
	// }

	return nil
}

// SimulateVendorCompliance simulates checking the compliance status of a vendor
func SimulateVendorCompliance(vendor string) bool {
	log.Printf("Simulating compliance check for vendor: %s", vendor)
	// Example: Randomly determine compliance status for testing
	isCompliant := time.Now().Unix()%2 == 0
	if isCompliant {
		log.Printf("Vendor %s is compliant", vendor)
	} else {
		log.Printf("Vendor %s is NOT compliant", vendor)
	}
	return isCompliant
}

// VerifyAutoRiskAssessment checks if AWS Inspector or a similar service is set up for automatic risk assessment
// 03.11.3

func VerifyAutoRiskAssessment(awsCfg aws.Config) error {
	svc := inspector2.NewFromConfig(awsCfg)

	// Check for enabled auto-assessment configurations
	input := &inspector2.ListAccountPermissionsInput{}
	resp, err := svc.ListAccountPermissions(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("error verifying automatic risk assessment configuration: %v", err)
	}

	// Loop through permissions to check if automatic assessments are enabled
	autoRiskAssessmentEnabled := false
	for _, permission := range resp.Permissions {
		if permission.Service == "inspector" && permission.Operation == "EnableAutomatedScanning" {
			autoRiskAssessmentEnabled = true
			break
		}
	}

	if !autoRiskAssessmentEnabled {
		log.Println("No automatic risk assessment tool configured. Please enable AWS Inspector with automated scanning.")
		return fmt.Errorf("automatic risk assessment not configured")
	}

	log.Println("Automatic risk assessment tool is configured.")
	return nil
}
