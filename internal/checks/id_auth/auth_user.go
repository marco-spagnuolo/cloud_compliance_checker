package id_auth

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// IAMServiceInterface is an interface for IAM operations (useful for testing)
type IAMServiceInterface interface {
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	GetUser(ctx context.Context, params *iam.GetUserInput, optFns ...func(*iam.Options)) (*iam.GetUserOutput, error)
}

// CheckAWSUserCompliance checks if AWS IAM users have MFA enabled and are compliant
func CheckAWSUserCompliance(cfg aws.Config, iamClient IAMServiceInterface) error {
	// Create a context for the requests
	ctx := context.TODO()

	// List all IAM users
	usersOutput, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return fmt.Errorf("failed to list users: %v", err)
	}

	for _, user := range usersOutput.Users {
		// For each user, check if MFA is enabled
		mfaOutput, err := iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		if err != nil {
			return fmt.Errorf("failed to list MFA devices for user %s: %v", *user.UserName, err)
		}

		if len(mfaOutput.MFADevices) == 0 {
			return fmt.Errorf("MFA is not enabled for user %s", *user.UserName)

		}
		fmt.Printf("User %s is compliant\n", *user.UserName)

	}
	return nil

}

// NewIAMClient creates a new IAM client
func NewIAMClient(cfg aws.Config) IAMServiceInterface {
	return iam.NewFromConfig(cfg)
}

func RunComplianceCheck(cfg aws.Config) error {
	fmt.Println("RunComplianceCheck started")

	iamClient := NewIAMClient(cfg)

	fmt.Println("Running compliance check on IAM users...") // Stampa di debug per vedere se arriva qui

	err := CheckAWSUserCompliance(cfg, iamClient)
	if err != nil {
		fmt.Printf("Compliance check failed: %v\n", err) // Se fallisce, dovresti vedere l'errore
		return fmt.Errorf("compliance check failed: %v", err)
	}

	fmt.Println("All users are compliant with MFA requirements.")
	return nil
}
