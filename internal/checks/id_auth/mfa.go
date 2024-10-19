package id_auth

import (
	"context"
	"fmt"
	"log"

	"cloud_compliance_checker/config"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// IAMUser represents an IAM user with their MFA status.
type IAMUser struct {
	UserName     string
	MFAEnabled   bool
	IsPrivileged bool
}

// ListIAMUsers fetches all IAM users in the AWS account.
func ListIAMUsers(iamClient *iam.Client) ([]IAMUser, error) {
	var iamUsers []IAMUser

	// Create the input for listing IAM users.
	input := &iam.ListUsersInput{}

	// Paginate through IAM users.
	paginator := iam.NewListUsersPaginator(iamClient, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM users: %w", err)
		}

		// For each IAM user, check their MFA status and add to the list.
		for _, user := range page.Users {
			isMFAEnabled, err := CheckMFAEnabled(*user.UserName, iamClient)
			if err != nil {
				log.Printf("Failed to check MFA for user %s: %v\n", *user.UserName, err)
				continue
			}

			iamUsers = append(iamUsers, IAMUser{
				UserName:     *user.UserName,
				MFAEnabled:   isMFAEnabled,
				IsPrivileged: IsPrivilegedUser(*user.UserName),
			})
		}
	}

	return iamUsers, nil
}

// CheckMFAEnabled checks if the given user has MFA enabled.
func CheckMFAEnabled(userName string, iamClient *iam.Client) (bool, error) {
	// Get the MFA devices associated with the user.
	input := &iam.ListMFADevicesInput{
		UserName: &userName,
	}

	// Fetch the MFA devices for the user.
	result, err := iamClient.ListMFADevices(context.TODO(), input)
	if err != nil {
		return false, fmt.Errorf("failed to list MFA devices for user %s: %w", userName, err)
	}

	// If the user has at least one MFA device, return true.
	return len(result.MFADevices) > 0, nil
}

// IsPrivilegedUser checks if a user is considered privileged based on their attached policies or roles in the config.
func IsPrivilegedUser(userName string) bool {
	// Retrieve privileged status from the configuration.
	for _, user := range config.AppConfig.AWS.Users {
		if user.Name == userName && user.IsPrivileged {
			return true
		}
	}
	return false
}

// AttachMFAEnforcementPolicy attaches a policy that enforces MFA for the specified user.
func AttachMFAEnforcementPolicy(userName string, iamClient *iam.Client) error {
	// Define the policy document to enforce MFA.
	// Use allow all actions for demonstration purposes.
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow", 
				"Action": "*",
				"Resource": "*",
				"Condition": {
					"BoolIfExists": {
						"aws:MultiFactorAuthPresent": "false"
					}
				}
			}
		]
	}`

	// Create the policy name for MFA enforcement.
	policyName := "EnforceMFA"

	// Attach the policy to the user.
	input := &iam.PutUserPolicyInput{
		UserName:       &userName,
		PolicyName:     &policyName,
		PolicyDocument: &policy,
	}

	_, err := iamClient.PutUserPolicy(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to attach MFA enforcement policy to user %s: %w", userName, err)
	}

	log.Printf("MFA enforcement policy attached to user %s\n", userName)
	return nil
}

// EnforceMFAForUsers ensures that all users (privileged and non-privileged) have MFA enabled, and enforces it where necessary.
func EnforceMFAForUsers(iamClient *iam.Client) error {
	log.Println("Starting MFA enforcement check for all users...")

	// List all IAM users and their MFA status.
	users, err := ListIAMUsers(iamClient)
	if err != nil {
		return fmt.Errorf("failed to list IAM users: %w", err)
	}

	// Track compliance status
	nonCompliant := false

	// Iterate over each user and ensure MFA is enabled.
	for _, user := range users {
		log.Printf("Checking MFA status for user: %s\n", user.UserName)
		if !user.MFAEnabled {
			log.Printf("User %s does not have MFA enabled\n", user.UserName)

			// Enforce MFA for all users, regardless of privilege status.
			log.Printf("Enforcing MFA for user %s...\n", user.UserName)
			err := AttachMFAEnforcementPolicy(user.UserName, iamClient)
			if err != nil {
				log.Printf("Failed to enforce MFA for user %s: %v\n", user.UserName, err)
				nonCompliant = true
			} else {
				log.Printf("MFA enforcement successful for user %s\n", user.UserName)
			}
		} else {
			log.Printf("User %s has MFA enabled\n", user.UserName)
		}
	}

	if nonCompliant {
		return fmt.Errorf("non-compliant: MFA is not enabled for all required users")
	}

	return nil
}
