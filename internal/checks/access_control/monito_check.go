package iampolicy

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// RunRemoteMonitoringCheck checks whether VPC Flow Logs and CloudTrail are enabled
func RunRemoteMonitoringCheck(cfg aws.Config) error {
	log.Println("Checking if VPC Flow Logs are enabled...")
	ec2Client := ec2.NewFromConfig(cfg)
	cloudtrailClient := cloudtrail.NewFromConfig(cfg)

	describeFlowLogsInput := &ec2.DescribeFlowLogsInput{}
	flowLogsOutput, err := ec2Client.DescribeFlowLogs(context.TODO(), describeFlowLogsInput)
	if err != nil {
		return fmt.Errorf("error retrieving VPC Flow Logs: %v", err)
	}

	log.Printf("Number of VPC Flow Logs found: %d\n", len(flowLogsOutput.FlowLogs))

	if len(flowLogsOutput.FlowLogs) == 0 {
		return fmt.Errorf("no VPC Flow Logs enabled: non-compliant")
	}

	log.Println("VPC Flow Logs are enabled.")

	trailStatusInput := &cloudtrail.GetTrailStatusInput{
		Name: aws.String("management-events"),
	}

	trailStatusOutput, err := cloudtrailClient.GetTrailStatus(context.TODO(), trailStatusInput)
	if err != nil {
		return fmt.Errorf("error retrieving CloudTrail status: %v", err)
	}

	if !*trailStatusOutput.IsLogging {
		return fmt.Errorf("CloudTrail is not enabled: non-compliant")
	}

	log.Println("CloudTrail is enabled and monitoring remote connections.")
	return nil
}
