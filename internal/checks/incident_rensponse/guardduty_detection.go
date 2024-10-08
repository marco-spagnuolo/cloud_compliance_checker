package incident_response

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// Function to detect incidents using GuardDuty
func DetectIncidents(cfg aws.Config) ([]types.Finding, error) {
	fmt.Println("Starting detection of incidents using GuardDuty...")

	guarddutyClient := guardduty.NewFromConfig(cfg)

	// List GuardDuty detectors
	fmt.Println("Listing GuardDuty detectors...")
	listDetectorsInput := &guardduty.ListDetectorsInput{}
	detectors, err := guarddutyClient.ListDetectors(context.TODO(), listDetectorsInput)
	if err != nil {
		return nil, fmt.Errorf("error listing detectors: %v", err)
	}
	if len(detectors.DetectorIds) == 0 {
		return nil, fmt.Errorf("no GuardDuty detectors found")
	}

	detectorId := detectors.DetectorIds[0]
	fmt.Printf("Found GuardDuty detector: %s\n", detectorId)

	// Delay to give GuardDuty time to process findings
	fmt.Println("Waiting for GuardDuty to detect any findings...")
	time.Sleep(5 * time.Second)

	// List recent findings (potential incidents)
	fmt.Println("Listing GuardDuty findings...")
	listFindingsInput := &guardduty.ListFindingsInput{
		DetectorId: &detectorId,
	}
	findings, err := guarddutyClient.ListFindings(context.TODO(), listFindingsInput)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve GuardDuty findings: %v", err)
	}
	if len(findings.FindingIds) == 0 {
		fmt.Println("No findings detected by GuardDuty")
		return nil, nil
	}

	var allFindings []types.Finding
	for _, findingId := range findings.FindingIds {
		fmt.Printf("Retrieving details for finding ID: %s...\n", findingId)
		getFindingsInput := &guardduty.GetFindingsInput{
			DetectorId: &detectorId,
			FindingIds: []string{findingId},
		}
		findingResults, err := guarddutyClient.GetFindings(context.TODO(), getFindingsInput)
		if err != nil {
			fmt.Printf("Error retrieving finding details for ID %s: %v\n", findingId, err)
			continue
		}
		allFindings = append(allFindings, findingResults.Findings...)
	}

	// Log and return detected findings
	fmt.Printf("\n--- Detected Incidents (GuardDuty Findings) ---\n")
	for _, finding := range allFindings {
		fmt.Printf("Incident: %s - %s\n", *finding.Title, *finding.Description)
		fmt.Printf("Severity: %f\n", *finding.Severity)
		fmt.Printf("Resource affected: %s\n", *finding.Resource.ResourceType)
	}
	fmt.Printf("Total findings detected: %d\n", len(allFindings))
	return allFindings, nil
}

// Detect incidents after attacks using GuardDuty
func detectIncidents(cfg aws.Config) error {
	findings, err := DetectIncidents(cfg)
	if err != nil {
		return fmt.Errorf("error detecting incidents: %v", err)
	}

	fmt.Println("--- Detected Incidents ---")
	for _, finding := range findings {
		fmt.Printf("Incident: %s\nDescription: %s\nSeverity: %f\n", *finding.Title, *finding.Description, *finding.Severity)
	}
	fmt.Printf("Total findings detected: %d\n", len(findings))
	return nil
}
