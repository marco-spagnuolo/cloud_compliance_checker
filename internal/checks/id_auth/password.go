package id_auth

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

/*
aws iam update-account-password-policy \
  --minimum-password-length 12 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password

*/
// Function to check password policy enforcement on AWS
func CheckPasswordPolicyEnforcement(cfg aws.Config) error {
	iamClient := iam.NewFromConfig(cfg)

	// Get the account password policy from AWS
	fmt.Println("Retrieving AWS IAM password policy...")
	passwordPolicyInput := &iam.GetAccountPasswordPolicyInput{}
	policy, err := iamClient.GetAccountPasswordPolicy(context.TODO(), passwordPolicyInput)

	// Handle the case when no password policy is set using type assertion
	if err != nil {
		if _, ok := err.(*types.NoSuchEntityException); ok {
			// If no password policy is set, print a friendly message and return
			fmt.Println("No password policy is set for the AWS account. Please configure a password policy to enforce complexity.")
			return nil // No need to return an error since this might be expected
		}
		// If there's any other error, print it
		fmt.Printf("Error retrieving password policy: %v\n", err)
		return fmt.Errorf("failed to get password policy: %v", err)
	}

	// If the password policy is nil (which should not happen after the above check)
	if policy.PasswordPolicy == nil {
		fmt.Println("No password policy found in the AWS account.")
		return fmt.Errorf("no password policy found in the AWS account")
	}

	// Start comparing the fetched AWS password policy with expected settings
	fmt.Printf("\n--- AWS Password Policy Retrieved ---\n")
	fmt.Printf("Minimum Password Length: %d\n", *policy.PasswordPolicy.MinimumPasswordLength)
	fmt.Printf("Require Numbers: %t\n", policy.PasswordPolicy.RequireNumbers)
	fmt.Printf("Require Symbols: %t\n", policy.PasswordPolicy.RequireSymbols)
	fmt.Printf("Require Uppercase Characters: %t\n", policy.PasswordPolicy.RequireUppercaseCharacters)
	fmt.Printf("Require Lowercase Characters: %t\n", policy.PasswordPolicy.RequireLowercaseCharacters)
	fmt.Println("--------------------------------------")

	// Checking AWS policy with expected values
	fmt.Printf("\nChecking AWS password policy against expected values...\n")

	// Check minimum password length (expected: 12)
	expectedMinLength := 12
	fmt.Printf("Checking minimum password length... AWS: %d, Expected: %d\n", *policy.PasswordPolicy.MinimumPasswordLength, expectedMinLength)
	if *policy.PasswordPolicy.MinimumPasswordLength != int32(expectedMinLength) {
		fmt.Printf("Result: NOT COMPLIANT\n")
		fmt.Printf("Mismatch: Minimum password length. AWS: %d, Expected: %d\n", *policy.PasswordPolicy.MinimumPasswordLength, expectedMinLength)
	} else {
		fmt.Println("Minimum password length matches.")
	}

	// Check if numbers are required (expected: true)
	expectedRequireNumbers := true
	fmt.Printf("Checking if numbers are required... AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireNumbers, expectedRequireNumbers)
	if policy.PasswordPolicy.RequireNumbers != expectedRequireNumbers {
		fmt.Printf("Result: NOT COMPLIANT\n")
		fmt.Printf("Mismatch: Require numbers. AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireNumbers, expectedRequireNumbers)
	} else {
		fmt.Println("Number requirement matches.")
	}

	// Check if symbols are required (expected: true)
	expectedRequireSymbols := true
	fmt.Printf("Checking if symbols are required... AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireSymbols, expectedRequireSymbols)
	if policy.PasswordPolicy.RequireSymbols != expectedRequireSymbols {
		fmt.Printf("Result: NOT COMPLIANT\n")
		fmt.Printf("Mismatch: Require symbols. AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireSymbols, expectedRequireSymbols)
	} else {
		fmt.Println("Symbol requirement matches.")
	}

	// Check if uppercase characters are required (expected: true)
	expectedRequireUppercase := true
	fmt.Printf("Checking if uppercase characters are required... AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireUppercaseCharacters, expectedRequireUppercase)
	if policy.PasswordPolicy.RequireUppercaseCharacters != expectedRequireUppercase {
		fmt.Printf("Result: NOT COMPLIANT\n")
		fmt.Printf("Mismatch: Require uppercase characters. AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireUppercaseCharacters, expectedRequireUppercase)
	} else {
		fmt.Println("Uppercase character requirement matches.")
	}

	// Check if lowercase characters are required (expected: true)
	expectedRequireLowercase := true
	fmt.Printf("Checking if lowercase characters are required... AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireLowercaseCharacters, expectedRequireLowercase)
	if policy.PasswordPolicy.RequireLowercaseCharacters != expectedRequireLowercase {
		fmt.Printf("Result: NOT COMPLIANT\n")
		fmt.Printf("Mismatch: Require lowercase characters. AWS: %t, Expected: %t\n", policy.PasswordPolicy.RequireLowercaseCharacters, expectedRequireLowercase)
	} else {
		fmt.Println("Lowercase character requirement matches.")
	}

	fmt.Println("\n--- Password policy check completed ---\n")

	return nil
}
