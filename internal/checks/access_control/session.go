package iampolicy

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// RunSessionTimeoutCheck performs the check for the NIST 3.1.10 requirement
func RunSessionTimeoutCheck(cfg aws.Config) error {
	log.Println("Starting check of active sessions...")
	SSMClient := ssm.NewFromConfig(cfg)
	listSessionsInput := &ssm.DescribeSessionsInput{
		State: "Active",
	}

	listSessionsOutput, err := SSMClient.DescribeSessions(context.TODO(), listSessionsInput)
	if err != nil {
		return fmt.Errorf("unable to list active sessions: %v", err)
	}

	log.Printf("Number of active sessions found: %d\n", len(listSessionsOutput.Sessions))

	for _, session := range listSessionsOutput.Sessions {
		inactivityDuration := time.Since(*session.StartDate)
		log.Printf("Session ID: %s, Inactivity: %v\n", *session.SessionId, inactivityDuration)

		if inactivityDuration > time.Duration(30)*time.Minute {
			terminateSessionInput := &ssm.TerminateSessionInput{
				SessionId: session.SessionId,
			}

			log.Printf("Attempting to terminate session %s due to inactivity...\n", *session.SessionId)
			_, err := SSMClient.TerminateSession(context.TODO(), terminateSessionInput)
			if err != nil {
				return fmt.Errorf("unable to terminate session %s: %v", *session.SessionId, err)
			}

			log.Printf("Session %s successfully terminated due to inactivity\n", *session.SessionId)
		} else {
			log.Printf("Session %s still active and not terminated due to inactivity\n", *session.SessionId)
		}
	}

	log.Println("Active session check completed.")
	return nil
}

func RunInactivitySessionCheck(cfg aws.Config, username string) error {
	iamClient := iam.NewFromConfig(cfg)

	log.Printf("Starting session policy check for IAM user %s...\n", username)

	listPoliciesInput := &iam.ListAttachedUserPoliciesInput{
		UserName: &username,
	}
	listPoliciesOutput, err := iamClient.ListAttachedUserPolicies(context.TODO(), listPoliciesInput)
	if err != nil {
		return fmt.Errorf("unable to list policies for user %s: %v", username, err)
	}

	found := false
	for _, policy := range listPoliciesOutput.AttachedPolicies {
		if *policy.PolicyName == "ForceSessionTimeout" {
			found = true
			break
		}
	}

	if !found {
		log.Printf("ERROR: ForceSessionTimeout policy is not attached to user %s\n", username)
		return fmt.Errorf("ForceSessionTimeout policy not found for user %s", username)
	}

	log.Printf("ForceSessionTimeout policy found for user %s\n", username)
	log.Println("IAM session policy check completed.")

	return nil
}
