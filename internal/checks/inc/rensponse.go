package inc

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// enableGuardDutySamples enables sample findings in GuardDuty
func enableGuardDutySamples(cfg aws.Config, detectorID string) error {
	client := guardduty.NewFromConfig(cfg)

	// Call the API to create sample findings
	input := &guardduty.CreateSampleFindingsInput{
		DetectorId: &detectorID,
	}
	_, err := client.CreateSampleFindings(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to create sample findings: %v", err)
	}

	fmt.Println("Sample findings have been successfully created.")
	return nil
}

// listGuardDutyFindings retrieves the list of finding IDs from GuardDuty
func listGuardDutyFindings(cfg aws.Config, detectorID string) ([]string, error) {
	client := guardduty.NewFromConfig(cfg)

	// Define input for ListFindings
	input := &guardduty.ListFindingsInput{
		DetectorId: &detectorID,
	}

	// Call ListFindings to retrieve findings
	resp, err := client.ListFindings(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %v", err)
	}

	return resp.FindingIds, nil
}

// getGuardDutyFindings retrieves the GuardDuty findings by IDs
func getGuardDutyFindings(cfg aws.Config, detectorID string, findingIds []string) ([]types.Finding, error) {
	client := guardduty.NewFromConfig(cfg)

	// Define input for GetFindings
	input := &guardduty.GetFindingsInput{
		DetectorId: &detectorID,
		FindingIds: findingIds,
	}

	// Call GetFindings to retrieve findings
	resp, err := client.GetFindings(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %v", err)
	}

	if len(resp.Findings) == 0 {
		fmt.Println("No findings available.")
	} else {
		fmt.Printf("Retrieved %d findings:\n", len(resp.Findings))
		for _, finding := range resp.Findings {
			fmt.Printf("Finding ID: %s, Type: %s, Severity: %f\n", *finding.Id, *finding.Type, *finding.Severity)
		}
	}

	return resp.Findings, nil
}

// checkLambdaInvocationLogs checks the CloudWatch logs to verify if the Lambda was triggered
func checkLambdaInvocationLogs(cfg aws.Config, logGroupName string) error {
	client := cloudwatchlogs.NewFromConfig(cfg)

	// Define input for DescribeLogStreams
	logStreamsInput := &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName: &logGroupName,
		OrderBy:      "LastEventTime",
		Descending:   aws.Bool(true), // Get the most recent log streams first
		Limit:        aws.Int32(1),   // Limit to the most recent log stream
	}

	// Retrieve the log streams
	logStreams, err := client.DescribeLogStreams(context.TODO(), logStreamsInput)
	if err != nil {
		return fmt.Errorf("failed to describe log streams: %v", err)
	}

	if len(logStreams.LogStreams) == 0 {
		fmt.Println("No log streams found for the Lambda function.")
		return nil
	}

	// Define input for GetLogEvents
	logStreamName := logStreams.LogStreams[0].LogStreamName
	getLogEventsInput := &cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  &logGroupName,
		LogStreamName: logStreamName,
		Limit:         aws.Int32(20), // Increase the limit to get more events
	}

	// Retrieve the log events
	logEvents, err := client.GetLogEvents(context.TODO(), getLogEventsInput)
	if err != nil {
		return fmt.Errorf("failed to get log events: %v", err)
	}

	// Check if there are any log events indicating the Lambda was invoked
	if len(logEvents.Events) > 0 {
		fmt.Println("Lambda was triggered successfully. Recent log events:")
		for _, event := range logEvents.Events {
			message := *event.Message
			fmt.Printf("Timestamp: %d, Message: %s\n", event.Timestamp, message)

			// Check for the specific error message regarding the fake instance ID
			if strings.Contains(message, "InvalidInstanceID.NotFound") {
				fmt.Println("Lambda executed correctly,the instance ID 'i-99999999' does not exist as expected.")
				return nil
			}
		}
	} else {
		fmt.Println("No log events found for the Lambda invocation.")
	}

	return fmt.Errorf("Lambda did not execute as expected")
}

// RunCheckIR is the main function to enable sample findings, retrieve findings, and check if the Lambda was triggered
func RunCheckIR(cfg aws.Config) error {
	// Assuming you have already a GuardDuty detector enabled, retrieve the detector ID
	client := guardduty.NewFromConfig(cfg)
	detectorInput := &guardduty.ListDetectorsInput{}
	detectorsOutput, err := client.ListDetectors(context.TODO(), detectorInput)
	if err != nil || len(detectorsOutput.DetectorIds) == 0 {
		log.Fatalf("unable to retrieve GuardDuty detectors, %v", err)
		return err
	}
	detectorID := detectorsOutput.DetectorIds[0]

	// Enable sample findings in GuardDuty
	err = enableGuardDutySamples(cfg, detectorID)
	if err != nil {
		log.Fatalf("Error enabling sample findings: %v", err)
		return err
	}

	// Sleep for a few seconds to let GuardDuty process the sample findings
	time.Sleep(10 * time.Second)

	// Retrieve the list of finding IDs
	findingIds, err := listGuardDutyFindings(cfg, detectorID)
	if err != nil {
		log.Fatalf("Error listing GuardDuty findings: %v", err)
		return err
	}

	// Retrieve the findings using the list of finding IDs
	_, err = getGuardDutyFindings(cfg, detectorID, findingIds)
	if err != nil {
		log.Fatalf("Error retrieving GuardDuty findings: %v", err)
		return err
	}

	// Wait a few seconds for the Lambda to be triggered by EventBridge
	time.Sleep(10 * time.Second)

	// Check if the Lambda was triggered by looking at the CloudWatch logs
	err = checkLambdaInvocationLogs(cfg, "/aws/lambda/guardduty-incident-response")
	if err != nil {
		log.Fatalf("Error checking Lambda invocation logs: %v", err)
		return err
	}

	return nil
}
