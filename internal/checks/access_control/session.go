package iampolicy

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// LoginAttempt represents a login attempt
type LoginAttempt struct {
	Username       string
	AttemptTime    time.Time
	IsSuccessful   bool
	FailedAttempts int
	IsLocked       bool
	LockoutTime    time.Time
}

var failedAttempts = map[string]*LoginAttempt{}

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

// RunLoginAttemptCheck checks failed login attempts and applies defined actions
func (c *IAMCheck) RunLoginAttemptCheck(isSuccess bool) error {
	now := time.Now()
	loginPolicy := config.AppConfig.AWS.LoginPolicy
	user := config.AppConfig.AWS.LoginPolicy.User
	// Check if the user has already made failed login attempts
	if _, exists := failedAttempts[user]; !exists {
		failedAttempts[user] = &LoginAttempt{
			Username:       user,
			AttemptTime:    now,
			IsSuccessful:   isSuccess,
			FailedAttempts: 0,
			IsLocked:       false,
		}
	}

	loginAttempt := failedAttempts[user]

	// If the account is locked, check if it should be unlocked
	if loginAttempt.IsLocked {
		if now.Sub(loginAttempt.LockoutTime) > time.Duration(loginPolicy.LockoutDurationMinutes)*time.Minute {
			// Unlock the account after the lockout period
			loginAttempt.IsLocked = false
			loginAttempt.FailedAttempts = 0
			log.Printf("Account %s automatically unlocked\n", user)
		} else {
			// The account is still locked
			log.Printf("Account %s is locked until %s\n", user, loginAttempt.LockoutTime.Add(time.Duration(loginPolicy.LockoutDurationMinutes)*time.Minute))
			return fmt.Errorf("account %s locked", user)
		}
	}

	// If the login attempt failed, increment the count
	if !isSuccess {
		loginAttempt.FailedAttempts++
		log.Printf("Failed login attempt for user %s. Total failed attempts: %d\n", user, loginAttempt.FailedAttempts)

		// Check if the maximum number of attempts has been exceeded
		if loginAttempt.FailedAttempts >= loginPolicy.MaxUnsuccessfulAttempts {
			// Apply the lockout action
			loginAttempt.IsLocked = true
			loginAttempt.LockoutTime = now

			// Check that `ActionOnLockout` is specified and apply the action
			switch loginPolicy.ActionOnLockout {
			case "lock_account":
				log.Printf("Account %s locked for %d minutes\n", user, loginPolicy.LockoutDurationMinutes)
			case "notify_admin":
				log.Printf("Administrator notified for account lockout %s\n", user)
			default:
				log.Printf("Unknown action for account lockout %s: %s\n", user, loginPolicy.ActionOnLockout)
				return fmt.Errorf("unknown lockout action: %s", loginPolicy.ActionOnLockout)
			}
			return fmt.Errorf("maximum failed login attempts reached for user %s", user)
		}
	} else {
		// If the login was successful, reset the failed attempts count
		loginAttempt.FailedAttempts = 0
	}

	return nil
}
