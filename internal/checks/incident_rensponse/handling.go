package incident_response

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/smithy-go" // Importing smithy-go for AWS error handling
)

/*
aws iam create-policy --policy-name SNSPublishPolicy \
--policy-document '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sns:Publish",
            "Resource": "arn:aws:sns:us-east-1:123456789012:IncidentAlert"
        }
    ]
}'
*/
// Function to detect incidents using GuardDuty
func DetectIncidents(cfg aws.Config) error {
	guarddutyClient := guardduty.NewFromConfig(cfg)

	// List GuardDuty detectors
	listDetectorsInput := &guardduty.ListDetectorsInput{}
	detectors, err := guarddutyClient.ListDetectors(context.TODO(), listDetectorsInput)
	if err != nil || len(detectors.DetectorIds) == 0 {
		return fmt.Errorf("no GuardDuty detectors found or error: %v", err)
	}
	detectorId := detectors.DetectorIds[0]

	// List recent findings (potential incidents)
	listFindingsInput := &guardduty.ListFindingsInput{
		DetectorId: &detectorId,
	}
	findings, err := guarddutyClient.ListFindings(context.TODO(), listFindingsInput)
	if err != nil {
		return fmt.Errorf("failed to retrieve GuardDuty findings: %v", err)
	}

	fmt.Printf("\n--- Detected Incidents (GuardDuty Findings) ---\n")
	for _, findingId := range findings.FindingIds {
		getFindingsInput := &guardduty.GetFindingsInput{
			DetectorId: &detectorId,
			FindingIds: []string{findingId},
		}
		findingResults, err := guarddutyClient.GetFindings(context.TODO(), getFindingsInput)
		if err != nil {
			fmt.Printf("Error retrieving finding details: %v\n", err)
			continue
		}
		for _, finding := range findingResults.Findings {
			fmt.Printf("Incident: %s - %s\n", *finding.Title, *finding.Description)
			fmt.Printf("Severity: %f\n", finding.Severity)
			fmt.Printf("Resource affected: %s\n", *finding.Resource.ResourceType)
			// Further actions like containment or alerting could be taken here
		}
	}
	return nil
}

// Function to respond to incidents (Containment and Eradication)
func RespondToIncidents(cfg aws.Config, incidentID string, action string) error {
	// Example: Isolate compromised EC2 instance (You can expand this based on the incident)
	fmt.Printf("Performing containment action for incident ID: %s. Action: %s\n", incidentID, action)
	// Implement action here (e.g., isolate EC2 instance, disable compromised credentials)
	return nil
}

// aws sns create-topic --name IncidentAlert
// Function to send an alert via SNS
func SendAlert(cfg aws.Config, topicArn string, message string) error {
	snsClient := sns.NewFromConfig(cfg)

	// Publish alert message to SNS topic
	publishInput := &sns.PublishInput{
		Message:  &message,
		TopicArn: &topicArn,
	}
	_, err := snsClient.Publish(context.TODO(), publishInput)
	if err != nil {
		// Handling errors properly with smithy-go for AWS SDK
		var awsErr *smithy.GenericAPIError
		if errors.As(err, &awsErr) {
			return fmt.Errorf("AWS error: %s", awsErr.ErrorMessage())
		}
		return fmt.Errorf("failed to send SNS alert: %v", err)
	}
	fmt.Println("Incident alert sent via SNS")
	return nil
}

// Main function to execute incident response workflow
func CheckIncidentHandling(cfg aws.Config) error {

	// Step 1: Detect incidents using GuardDuty
	err := DetectIncidents(cfg)
	if err != nil {
		log.Printf("Error detecting incidents: %v", err)
		return err
	}

	// Step 2: Respond to a specific incident (as an example)
	err = RespondToIncidents(cfg, "incident-id-example", "Isolate EC2 Instance")
	if err != nil {
		log.Printf("Error responding to incident: %v", err)
		return err
	}

	// Step 3: Send alert using SNS
	err = SendAlert(cfg, "arn:aws:sns:us-east-1:682033472444:IncidentAlert", "Incident detected and action taken.") // TODO ask user or get from config
	if err != nil {
		log.Printf("Error sending alert: %v", err)
		return err
	}
	return nil
}
