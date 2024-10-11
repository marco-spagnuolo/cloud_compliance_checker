package incident_response

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	// **List only non-archived findings (those in active or suppressed state)**
	fmt.Println("Listing non-archived GuardDuty findings...")
	listFindingsInput := &guardduty.ListFindingsInput{
		DetectorId: &detectorId,
		FindingCriteria: &types.FindingCriteria{
			Criterion: map[string]types.Condition{
				"service.archived": {
					Eq: []string{"false"}, // This ensures only non-archived findings are retrieved
				},
			},
		},
	}
	findings, err := guarddutyClient.ListFindings(context.TODO(), listFindingsInput)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve GuardDuty findings: %v", err)
	}
	if len(findings.FindingIds) == 0 {
		fmt.Println("No non-archived findings detected by GuardDuty")
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
	fmt.Printf("\n--- Detected Incidents (Non-Archived GuardDuty Findings) ---\n")
	for _, finding := range allFindings {
		// Parse and format the timestamp of the event
		eventTime, err := time.Parse(time.RFC3339, *finding.Service.EventFirstSeen)
		if err != nil {
			fmt.Printf("Error parsing event time for finding ID %s: %v\n", *finding.Id, err)
			continue
		}
		formattedTime := eventTime.Format("2006-01-02 15:04:05")

		// Print incident details including the event time
		fmt.Printf("Incident: %s - %s\n", *finding.Title, *finding.Description)
		fmt.Printf("Severity: %f\n", *finding.Severity)
		fmt.Printf("Resource affected: %s\n", *finding.Resource.ResourceType)
		fmt.Printf("Time of event: %s\n", formattedTime)
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

// collectAndSaveGuardDutyFindings raccoglie gli incidenti di GuardDuty e li salva in un file JSON
func collectAndSaveGuardDutyFindings(cfg aws.Config) error {
	client := guardduty.NewFromConfig(cfg)

	// Recupera l'elenco dei detector GuardDuty
	listDetectorsInput := &guardduty.ListDetectorsInput{}
	detectors, err := client.ListDetectors(context.TODO(), listDetectorsInput)
	if err != nil {
		return fmt.Errorf("failed to list GuardDuty detectors: %v", err)
	}

	if len(detectors.DetectorIds) == 0 {
		return fmt.Errorf("no GuardDuty detectors found")
	}

	// Prendi il primo detector per esempio
	detectorID := detectors.DetectorIds[0]
	fmt.Printf("Found GuardDuty detector: %s\n", detectorID)

	// Recupera i findings (incidenti)
	findingsInput := &guardduty.ListFindingsInput{
		DetectorId: &detectorID,
	}
	findings, err := client.ListFindings(context.TODO(), findingsInput)
	if err != nil {
		return fmt.Errorf("failed to list GuardDuty findings: %v", err)
	}

	if len(findings.FindingIds) == 0 {
		fmt.Println("No findings found in GuardDuty.")
		return nil
	}

	// Dettagli degli incidenti
	findingDetails := []map[string]interface{}{}
	for _, findingID := range findings.FindingIds {
		getFindingInput := &guardduty.GetFindingsInput{
			DetectorId: &detectorID,
			FindingIds: []string{findingID},
		}
		findingOutput, err := client.GetFindings(context.TODO(), getFindingInput)
		if err != nil {
			return fmt.Errorf("failed to get details for finding ID %s: %v", findingID, err)
		}
		for _, finding := range findingOutput.Findings {
			eventTime, err := time.Parse(time.RFC3339, *finding.Service.EventFirstSeen)
			if err != nil {
				fmt.Printf("Error parsing event time for finding ID %s: %v\n", *finding.Id, err)
				continue
			}
			formattedTime := eventTime.Format("2006-01-02 15:04:05")

			findingDetails = append(findingDetails, map[string]interface{}{
				"ID":          finding.Id,
				"Type":        finding.Type,
				"Description": finding.Description,
				"Severity":    finding.Severity,
				"Time":        formattedTime,
			})

		}

	}

	// Salva i findings in un file JSON
	fileName := "guardduty_findings.json"
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(findingDetails)
	if err != nil {
		return fmt.Errorf("failed to encode findings to JSON: %v", err)
	}

	fmt.Printf("Findings saved to file: %s\n", fileName)

	// Carica il file JSON su S3
	fmt.Println("Uploading findings to S3...")
	err = uploadToS3(cfg, "guarduty-bucket--findings", fileName)
	if err != nil {
		return fmt.Errorf("failed to upload findings to S3: %v", err)
	}

	return nil
}
