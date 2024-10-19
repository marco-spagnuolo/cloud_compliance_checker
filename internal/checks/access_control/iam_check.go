package iampolicy

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// IAMCheck is a struct that contains the AWS clients required for the IAM checks
type IAMCheck struct {
	EC2Client        *ec2.Client
	S3Client         *s3.Client
	IAMClient        *iam.Client
	CloudTrailClient *cloudtrail.Client
}

// NewIAMCheck initializes a new IAMCheck struct with the provided AWS configuration
func NewIAMCheck(cfg aws.Config) *IAMCheck {
	return &IAMCheck{
		EC2Client: ec2.NewFromConfig(cfg),
		S3Client:  s3.NewFromConfig(cfg),
		IAMClient: iam.NewFromConfig(cfg),
	}
}

// RunCheckPolicies checks if the IAM users have the correct policies attached
// 03.01.01 Account Management
func RunCheckPolicies(cfg aws.Config) error {

	iamclient := iam.NewFromConfig(cfg)

	listUsersOutput, err := iamclient.ListUsers(context.TODO(), &iam.ListUsersInput{})
	if err != nil {
		return LogAndReturnError("unable to list users", err)
	}

	usersFromConfig := config.AppConfig.AWS.Users
	var nonConformingUsers []string

	for _, awsUser := range listUsersOutput.Users {
		log.Printf("=======> Check for AWS user: %s\n", *awsUser.UserName)
		attachedPoliciesOutput, err := iamclient.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
			UserName: awsUser.UserName,
		})
		if err != nil {
			return LogAndReturnError(fmt.Sprintf("unable to list attached policies for user %s", *awsUser.UserName), err)
		}

		var configUser *config.User
		for i, user := range usersFromConfig {
			if user.Name == *awsUser.UserName {
				configUser = &usersFromConfig[i]
				break
			}
		}

		if configUser == nil {
			log.Printf("User %s not found in config file\n", *awsUser.UserName)
			nonConformingUsers = append(nonConformingUsers, *awsUser.UserName)
			continue
		}

		if len(configUser.Policies) == 0 {
			log.Printf("ERROR: User %s has no policies defined in the configuration file\n", *awsUser.UserName)
			nonConformingUsers = append(nonConformingUsers, configUser.Name)
			continue
		}

		for _, awsPolicy := range attachedPoliciesOutput.AttachedPolicies {
			log.Printf("=======> User %s has the policy: %s\n", *awsUser.UserName, *awsPolicy.PolicyName)

			if !ContainsString(configUser.Policies, *awsPolicy.PolicyName) {
				log.Printf("ERROR: Policy %s assigned to user %s is not defined in the configuration file\n", *awsPolicy.PolicyName, *awsUser.UserName)
				nonConformingUsers = append(nonConformingUsers, configUser.Name)
				continue
			}
		}

		for _, configPolicy := range configUser.Policies {
			found := false
			for _, awsPolicy := range attachedPoliciesOutput.AttachedPolicies {
				if configPolicy == *awsPolicy.PolicyName {
					found = true
					break
				}
			}
			if !found {
				log.Printf("ERROR: Policy %s defined in the configuration file is not assigned to user %s\n", configPolicy, *awsUser.UserName)
				nonConformingUsers = append(nonConformingUsers, configUser.Name)
			}
		}
	}

	// If there are non-conforming users, return an error
	if len(nonConformingUsers) > 0 {
		return fmt.Errorf("non-conforming users found: %v", nonConformingUsers)
	}

	return nil
}

// RunCheckAcceptedPolicies checks if the accepted policies are present on AWS
// 03.01.02 Access Enforcement
func (c *IAMCheck) RunCheckAcceptedPolicies() error {

	// Load the accepted policies from the configuration file
	acceptedPolicies := config.AppConfig.AWS.AcceptedPolicies

	// List the managed policies on AWS
	listPoliciesOutput, err := c.IAMClient.ListPolicies(context.TODO(), &iam.ListPoliciesInput{})
	if err != nil {
		return fmt.Errorf("unable to list policies on AWS: %v", err)
	}

	// Log to verify the policies actually present on AWS
	log.Printf("INFO: Policies found on AWS:")
	for _, policy := range listPoliciesOutput.Policies {
		log.Printf("Policy found: %s/d", *policy.PolicyName)
	}

	policiesOnAWS := MapAWSManagedPolicies(listPoliciesOutput.Policies)

	// Compare the accepted policies with those actually present on AWS
	for _, acceptedPolicy := range acceptedPolicies {
		if _, exists := policiesOnAWS[acceptedPolicy]; !exists {
			log.Printf("ERROR: Accepted policy %s not found on AWS", acceptedPolicy)
			return fmt.Errorf("accepted policy %s not found on AWS", acceptedPolicy)
		}
	}

	log.Println("INFO: All accepted policies are compliant on AWS")
	return nil
}

// RunCheckCUIFlow checks the security groups and S3 buckets for compliance
// 03.01.03
func RunCheckCUIFlow(cfg aws.Config) error {

	securityGroupsFromConfig := config.AppConfig.AWS.SecurityGroups
	ec2Client := ec2.NewFromConfig(cfg)

	// List the security groups from AWS
	describeSGOutput, err := ec2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return LogAndReturnError("unable to list security groups", err)
	}

	// Pass the loaded data to the RunSecurityGroupCheck function
	if err := RunSecurityGroupCheck(securityGroupsFromConfig, describeSGOutput.SecurityGroups); err != nil {
		return LogAndReturnError("error during security group check", err)
	}

	log.Println("===== Security group check completed =====")

	if err := RunS3BucketCheck(cfg); err != nil {
		return LogAndReturnError("error during S3 bucket check", err)
	}
	log.Println("===== S3 bucket check completed =====")

	return nil
}

// RunCheckSeparateDuties performs the check for separation of duties
// 3.0.4 Separation of Duties
func (c *IAMCheck) RunCheckSeparateDuties() error {
	criticalRoles := config.AppConfig.AWS.CriticalRoles

	listRolesOutput, err := c.IAMClient.ListRoles(context.TODO(), &iam.ListRolesInput{})
	if err != nil {
		return LogAndReturnError("unable to list IAM roles on AWS", err)
	}

	roleFunctionMap := MapRolesToFunctions(listRolesOutput.Roles, c.IAMClient)

	for _, criticalRole := range criticalRoles {
		if err := VerifyCriticalRoleCompliance(criticalRole, roleFunctionMap); err != nil {
			return err
		}
	}

	log.Println("INFO: Separation of duties check successfully completed.")
	return nil
}

// RunPrivilegeCheck performs the check for privileges
// 3.0.5
func (c *IAMCheck) RunPrivilegeCheck() error {
	// Load the users and their policies from the configuration
	usersFromConfig := config.AppConfig.AWS.Users

	// Check privileges and security functions for each user
	for _, user := range usersFromConfig {
		log.Printf("Checking privileges for user: %s\n", user.Name)

		// Check that each security function corresponds to an assigned policy
		for _, sf := range user.SecurityFunctions {
			log.Printf("Checking security function %s for user %s\n", sf, user.Name)

			// Variable to determine if a corresponding policy was found
			found := false

			// Check if there is a policy that covers the security function
			for _, policy := range user.Policies {
				log.Printf("Checking policy %s for security function %s\n", policy, sf)

				if policy == sf {
					found = true
					break
				}
			}

			// If no corresponding policy is found for the security function, log the error
			if !found {
				log.Printf("ERROR: Security function %s for user %s is not covered by any policy\n", sf, user.Name)
				return fmt.Errorf("security functions not compliant for user %s", user.Name)
			}
		}

	}

	return nil
}

// RunPrivilegeAccountCheck performs the check for the NIST 3.1.6 requirement
func (c *IAMCheck) RunPrivilegeAccountCheck() error {
	usersFromConfig := config.AppConfig.AWS.Users

	for _, user := range usersFromConfig {
		log.Printf("Checking privileges for user: %s\n", user.Name)

		// If the user is not privileged but has security functions
		if !user.IsPrivileged && len(user.SecurityFunctions) > 0 {
			for _, sf := range user.SecurityFunctions {
				log.Printf("ERROR: User %s is not privileged but has access to security function: %s\n", user.Name, sf)
			}
			return fmt.Errorf("non-privileged user %s with access to security functions", user.Name)
		}

		// If the user is privileged but has no security functions
		if user.IsPrivileged && len(user.SecurityFunctions) == 0 {
			log.Printf("ERROR: Privileged user %s has no assigned security functions\n", user.Name)
			return fmt.Errorf("privileged user %s without security functions", user.Name)
		}

		// Check that the policies match the security functions
		for _, sf := range user.SecurityFunctions {
			if !ContainsString(user.Policies, sf) {
				log.Printf("ERROR: Policy %s for user %s does not match the security function %s\n", user.Policies, user.Name, sf)
				return fmt.Errorf("security functions not compliant for user %s", user.Name)
			}
		}
	}

	log.Println("Privilege check successfully completed")
	return nil
}

// RunPrivilegedFunctionCheck performs the check for the NIST 3.1.7 requirement
func (c *IAMCheck) RunPrivilegedFunctionCheck() error {

	for _, user := range config.AppConfig.AWS.Users {
		log.Printf("Checking privileges for user: %s\n", user.Name)

		// Check if a non-privileged user has access to privileged functions
		if !user.IsPrivileged && len(user.SecurityFunctions) > 0 {
			for _, sf := range user.SecurityFunctions {
				// If the non-privileged user has a security function, log the error
				log.Printf("ERROR: Non-privileged user %s has access to security function: %s\n", user.Name, sf)
				return fmt.Errorf("non-privileged user %s with access to security functions: %s", user.Name, sf)
			}
		}
	}

	// All checks passed
	log.Println("Privileged function check successfully completed.")
	return nil
}
