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
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html amazon inspector agent needed on machines
// TODO - change to linux version compatible with amazon inspector without registration
// CheckAndStartVulnerabilityScan verifies if a scan is due and starts it
func CheckAndStartVulnerabilityScan(awsCfg aws.Config) error {
	log.Printf("Initiating vulnerability scan - Frequency: %s", config.AppConfig.AWS.RiskAssessmentConfig.VulnerabilityScanning.Frequency)
	// lastRun, err := GetLastRun(config.AppConfig.AWS.RiskAssessmentConfig.VulnerabilityScanning.AssessmentTemplateArn, awsCfg)
	// if err != nil {
	// 	log.Printf("Error retrieving last scan: %v", err)
	// }
	// Forcing scan to always run for demonstration
	if false {
		log.Println("Vulnerability scan not needed yet.")

	} else {
		err := StartInspectorScan(config.AppConfig.AWS.RiskAssessmentConfig.VulnerabilityScanning.AssessmentTemplateArn, awsCfg)
		if err != nil {
			return err
		}
		err = MonitorVulnerabilities(awsCfg)
		if err != nil {
			return err
		}
	}

	return nil
}

// StartInspectorScan starts a scan with AWS Inspector using the provided ARN
func StartInspectorScan(templateArn string, awsCfg aws.Config) error {
	log.Printf("Starting AWS Inspector scan with template: %s", templateArn)
	svc := inspector.NewFromConfig(awsCfg)

	input := &inspector.StartAssessmentRunInput{
		AssessmentTemplateArn: aws.String(templateArn),
		AssessmentRunName:     aws.String("ScheduledScan-" + time.Now().Format("20060102-150405")),
	}

	_, err := svc.StartAssessmentRun(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to start scan: %v", err)
		return fmt.Errorf("failed to start scan: %v", err)
	}

	log.Println("Vulnerability scan initiated successfully.")
	return nil
}

// MonitorVulnerabilities triggers remediation tasks for all findings
func MonitorVulnerabilities(awsCfg aws.Config) error {
	// Use AWS Inspector2 to monitor findings
	svc := inspector2.NewFromConfig(awsCfg)

	input := &inspector2.ListFindingsInput{
		FilterCriteria: &types.FilterCriteria{
			Severity: []types.StringFilter{
				{
					Comparison: types.StringComparisonEquals,
					Value:      aws.String("CRITICAL"),
				},
				{
					Comparison: types.StringComparisonEquals,
					Value:      aws.String("HIGH"),
				},
				{
					Comparison: types.StringComparisonEquals,
					Value:      aws.String("MEDIUM"),
				},
				{
					Comparison: types.StringComparisonEquals,
					Value:      aws.String("LOW"),
				},
				{
					Comparison: types.StringComparisonEquals,
					Value:      aws.String("INFORMATIONAL"),
				},
			},
		},
	}

	resp, err := svc.ListFindings(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("error listing findings: %v", err)
	}

	for _, finding := range resp.Findings {
		log.Printf("Finding: %s, Severity: %s, Resource: %s, Description: %s",
			*finding.Title, finding.Severity, *finding.Resources[0].Id, *finding.Description)
		// Trigger remediation process based on resource
		RemediateVulnerability(finding)
	}

	if len(resp.Findings) == 0 {
		log.Println("No findings detected.")
	}

	return nil
}

// RemediateVulnerability initiates actions to fix the detected vulnerabilities
func RemediateVulnerability(finding types.Finding) {
	log.Printf("Initiating remediation for finding: %s", *finding.Title)
	// Example: Automatically patch or reconfigure the resource
}

// getFrequencyDuration converts frequency string to time.Duration
func getFrequencyDuration(frequency string) time.Duration {
	switch frequency {
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 30 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}
