package incident_response

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// Send an SNS alert with the incident response status
func SendAlert(cfg aws.Config, topicArn, message string) error {
	snsClient := sns.NewFromConfig(cfg)
	publishInput := &sns.PublishInput{Message: &message, TopicArn: &topicArn}
	_, err := snsClient.Publish(context.TODO(), publishInput)
	if err != nil {
		return fmt.Errorf("failed to send SNS alert: %v", err)
	}
	return nil
}
