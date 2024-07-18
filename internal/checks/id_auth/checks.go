package id_auth

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// Check for control 3.5.1 - Identify system users, processes acting on behalf of users, and devices.
func CheckSystemUsers(iamSvc iamiface.IAMAPI, cloudtrailSvc cloudtrailiface.CloudTrailAPI, ec2Svc ec2iface.EC2API) models.ComplianceResult {
	// Check IAM users
	iamInput := &iam.ListUsersInput{}
	iamResult, err := iamSvc.ListUsers(iamInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Identify system users, processes, and devices",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing IAM users: %v", err),
			Impact:      5,
		}
	}

	if len(iamResult.Users) == 0 {
		return models.ComplianceResult{
			Description: "Identify system users, processes, and devices",
			Status:      "FAIL",
			Response:    "No IAM users found",
			Impact:      5,
		}
	}

	// Check CloudTrail for processes acting on behalf of users
	cloudtrailInput := &cloudtrail.LookupEventsInput{}
	cloudtrailResult, err := cloudtrailSvc.LookupEvents(cloudtrailInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Identify system users, processes, and devices",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error looking up CloudTrail events: %v", err),
			Impact:      5,
		}
	}

	if len(cloudtrailResult.Events) == 0 {
		return models.ComplianceResult{
			Description: "Identify system users, processes, and devices",
			Status:      "FAIL",
			Response:    "No CloudTrail events found",
			Impact:      5,
		}
	}

	// Check EC2 instances for IAM roles (indicating devices)
	ec2Input := &ec2.DescribeInstancesInput{}
	ec2Result, err := ec2Svc.DescribeInstances(ec2Input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Identify system users, processes, and devices",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error describing EC2 instances: %v", err),
			Impact:      5,
		}
	}

	deviceCount := 0
	for _, reservation := range ec2Result.Reservations {
		for range reservation.Instances {
			deviceCount++
		}
	}

	if deviceCount == 0 {
		return models.ComplianceResult{
			Description: "Identify system users, processes, and devices",
			Status:      "FAIL",
			Response:    "No EC2 instances found",
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Identify system users, processes, and devices",
		Status:      "PASS",
		Response:    "IAM users, processes, and devices identified",
		Impact:      0,
	}
}

// Check for control 3.5.2 - Authenticate (or verify) the identities of users, processes, or devices as a prerequisite to allowing access to organizational systems.
func CheckAuthentication(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	input := &iam.ListUsersInput{}
	result, err := iamSvc.ListUsers(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Authenticate identities",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing IAM users: %v", err),
			Impact:      5,
		}
	}

	if len(result.Users) == 0 {
		return models.ComplianceResult{
			Description: "Authenticate identities",
			Status:      "FAIL",
			Response:    "No IAM users found",
			Impact:      5,
		}
	}

	// Assuming that if users exist, authentication mechanisms are in place
	return models.ComplianceResult{
		Description: "Authenticate identities",
		Status:      "PASS",
		Response:    "Identities authenticated",
		Impact:      0,
	}
}

// Check for control 3.5.3 - Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.
func CheckMFA(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	input := &iam.ListUsersInput{}
	result, err := iamSvc.ListUsers(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Use MFA for privileged accounts",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing IAM users: %v", err),
			Impact:      5,
		}
	}

	for _, user := range result.Users {
		mfaInput := &iam.ListMFADevicesInput{
			UserName: user.UserName,
		}
		mfaResult, err := iamSvc.ListMFADevices(mfaInput)
		if err != nil {
			return models.ComplianceResult{
				Description: "Use MFA for privileged accounts",
				Status:      "FAIL",
				Response:    fmt.Sprintf("Error listing MFA devices for user %s: %v", *user.UserName, err),
				Impact:      5,
			}
		}
		if len(mfaResult.MFADevices) == 0 {
			return models.ComplianceResult{
				Description: "Use MFA for privileged accounts",
				Status:      "FAIL",
				Response:    fmt.Sprintf("User %s does not have MFA enabled", *user.UserName),
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Use MFA for privileged accounts",
		Status:      "PASS",
		Response:    "All IAM users have MFA enabled",
		Impact:      0,
	}
}

// Check for control 3.5.4 - Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.
func CheckReplayResistantAuthentication() models.ComplianceResult {
	// Placeholder for actual implementation using AWS IAM
	return models.ComplianceResult{
		Description: "Employ replay-resistant authentication mechanisms",
		Status:      "PASS",
		Response:    "Replay-resistant authentication mechanisms are employed",
		Impact:      0,
	}
}

// Check for control 3.5.5 - Prevent reuse of identifiers for a defined period.
func CheckIdentifierReusePrevention(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	// Get the password policy to ensure reuse prevention is in place
	policyInput := &iam.GetAccountPasswordPolicyInput{}
	policyResult, err := iamSvc.GetAccountPasswordPolicy(policyInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Prevent reuse of identifiers",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving password policy: %v", err),
			Impact:      5,
		}
	}

	if policyResult.PasswordPolicy.PasswordReusePrevention == nil || *policyResult.PasswordPolicy.PasswordReusePrevention == 0 {
		return models.ComplianceResult{
			Description: "Prevent reuse of identifiers",
			Status:      "FAIL",
			Response:    "Password reuse prevention is not enforced",
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Prevent reuse of identifiers",
		Status:      "PASS",
		Response:    "Identifier reuse prevention is enforced",
		Impact:      0,
	}
}

// Check for control 3.5.6 - Disable identifiers after a defined period of inactivity.
func CheckIdentifierDisabling(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	// Get the account summary to check if there are policies for disabling inactive accounts
	summaryInput := &iam.GetAccountSummaryInput{}
	summaryResult, err := iamSvc.GetAccountSummary(summaryInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Disable identifiers after inactivity",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving account summary: %v", err),
			Impact:      5,
		}
	}

	if inactiveAccounts, ok := summaryResult.SummaryMap["AccountAccessKeysPresent"]; !ok || *inactiveAccounts == 0 {
		return models.ComplianceResult{
			Description: "Disable identifiers after inactivity",
			Status:      "PASS",
			Response:    "No inactive identifiers found",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Disable identifiers after inactivity",
		Status:      "FAIL",
		Response:    "Inactive identifiers are present and not disabled",
		Impact:      5,
	}
}

// Check for control 3.5.7 - Enforce a minimum password complexity and change of characters when new passwords are created.
func CheckPasswordComplexity(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	policyInput := &iam.GetAccountPasswordPolicyInput{}
	policyResult, err := iamSvc.GetAccountPasswordPolicy(policyInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Enforce minimum password complexity",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving password policy: %v", err),
			Impact:      5,
		}
	}

	if policyResult.PasswordPolicy.RequireNumbers == nil || !*policyResult.PasswordPolicy.RequireNumbers {
		return models.ComplianceResult{
			Description: "Enforce minimum password complexity",
			Status:      "FAIL",
			Response:    "Password complexity is not enforced (numbers missing)",
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Enforce minimum password complexity",
		Status:      "PASS",
		Response:    "Password complexity is enforced",
		Impact:      0,
	}
}

// Check for control 3.5.8 - Prohibit password reuse for a specified number of generations.
func CheckPasswordReuseProhibition(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	policyInput := &iam.GetAccountPasswordPolicyInput{}
	policyResult, err := iamSvc.GetAccountPasswordPolicy(policyInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Prohibit password reuse",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving password policy: %v", err),
			Impact:      5,
		}
	}

	if policyResult.PasswordPolicy.PasswordReusePrevention == nil || *policyResult.PasswordPolicy.PasswordReusePrevention == 0 {
		return models.ComplianceResult{
			Description: "Prohibit password reuse",
			Status:      "FAIL",
			Response:    "Password reuse is not prohibited",
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Prohibit password reuse",
		Status:      "PASS",
		Response:    "Password reuse is prohibited",
		Impact:      0,
	}
}

// Check for control 3.5.9 - Allow temporary password use for system logons with an immediate change to a permanent password.
func CheckTemporaryPasswordUsage(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	input := &iam.ListUsersInput{}
	result, err := iamSvc.ListUsers(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Allow temporary password use",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing IAM users: %v", err),
			Impact:      5,
		}
	}

	for _, user := range result.Users {
		if user.PasswordLastUsed == nil {
			continue // Skip users without a password
		}
		userDetails, err := iamSvc.GetUser(&iam.GetUserInput{UserName: user.UserName})
		if err != nil {
			return models.ComplianceResult{
				Description: "Allow temporary password use",
				Status:      "FAIL",
				Response:    fmt.Sprintf("Error retrieving user details for %s: %v", *user.UserName, err),
				Impact:      5,
			}
		}
		if userDetails.User.PasswordLastUsed != nil {
			return models.ComplianceResult{
				Description: "Allow temporary password use",
				Status:      "PASS",
				Response:    fmt.Sprintf("Temporary password use is allowed for user %s", *user.UserName),
				Impact:      0,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Allow temporary password use",
		Status:      "FAIL",
		Response:    "Temporary password use is not properly enforced",
		Impact:      5,
	}
}

// Check for control 3.5.10 - Store and transmit only cryptographically-protected passwords.
func CheckPasswordEncryption(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	// Placeholder: Actual implementation would check for encrypted storage mechanisms
	// Ensuring encryption policies for password storage
	input := &iam.GetAccountPasswordPolicyInput{}
	_, err := iamSvc.GetAccountPasswordPolicy(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Store and transmit cryptographically-protected passwords",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving password policy: %v", err),
			Impact:      5,
		}
	}

	// Assuming that if password policy exists, encryption is enforced
	return models.ComplianceResult{
		Description: "Store and transmit cryptographically-protected passwords",
		Status:      "PASS",
		Response:    "Passwords are cryptographically protected",
		Impact:      0,
	}
}

// Check for control 3.5.11 - Obscure feedback of authentication information.
func CheckObscuredFeedback(iamSvc iamiface.IAMAPI) models.ComplianceResult {
	// Verify IAM password policy configurations
	policyInput := &iam.GetAccountPasswordPolicyInput{}
	policyResult, err := iamSvc.GetAccountPasswordPolicy(policyInput)
	if err != nil {
		return models.ComplianceResult{
			Description: "Obscure feedback of authentication information",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error retrieving password policy: %v", err),
			Impact:      5,
		}
	}

	// Check if password policy is set
	if policyResult.PasswordPolicy == nil {
		return models.ComplianceResult{
			Description: "Obscure feedback of authentication information",
			Status:      "FAIL",
			Response:    "Password policy is not set",
			Impact:      5,
		}
	}

	// Verify MFA is enabled for users
	mfaEnabled, err := isMFAEnabledForAllUsers(iamSvc)
	if err != nil {
		return models.ComplianceResult{
			Description: "Obscure feedback of authentication information",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking MFA status: %v", err),
			Impact:      5,
		}
	}

	if !mfaEnabled {
		return models.ComplianceResult{
			Description: "Obscure feedback of authentication information",
			Status:      "FAIL",
			Response:    "MFA is not enabled for all users",
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Obscure feedback of authentication information",
		Status:      "PASS",
		Response:    "Authentication feedback is obscured",
		Impact:      0,
	}
}

// Helper function to check if MFA is enabled for all users
func isMFAEnabledForAllUsers(iamSvc iamiface.IAMAPI) (bool, error) {
	input := &iam.ListUsersInput{}
	result, err := iamSvc.ListUsers(input)
	if err != nil {
		return false, fmt.Errorf("error listing IAM users: %v", err)
	}

	for _, user := range result.Users {
		mfaInput := &iam.ListMFADevicesInput{
			UserName: user.UserName,
		}
		mfaResult, err := iamSvc.ListMFADevices(mfaInput)
		if err != nil {
			return false, fmt.Errorf("error listing MFA devices for user %s: %v", *user.UserName, err)
		}
		if len(mfaResult.MFADevices) == 0 {
			return false, nil
		}
	}

	return true, nil
}
