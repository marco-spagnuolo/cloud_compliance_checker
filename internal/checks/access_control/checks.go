package iampolicy

// import (
// 	"cloud_compliance_checker/config"
// 	"context"
// 	"fmt"
// 	"log"
// 	"time"

// 	"github.com/aws/aws-sdk-go-v2/aws"
// 	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
// 	"github.com/aws/aws-sdk-go-v2/service/ec2"
// 	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
// 	"github.com/aws/aws-sdk-go-v2/service/iam"
// 	"github.com/aws/aws-sdk-go-v2/service/s3"
// 	"github.com/aws/aws-sdk-go-v2/service/ssm"
// )

// // IAMCheck is a struct that contains the AWS clients required for the IAM checks
// type IAMCheck struct {
// 	EC2Client        *ec2.Client
// 	S3Client         *s3.Client
// 	IAMClient        *iam.Client
// 	CloudTrailClient *cloudtrail.Client
// }

// // NewIAMCheck initializes a new IAMCheck struct with the provided AWS configuration
// func NewIAMCheck(cfg aws.Config) *IAMCheck {
// 	return &IAMCheck{
// 		EC2Client: ec2.NewFromConfig(cfg),
// 		S3Client:  s3.NewFromConfig(cfg),
// 		IAMClient: iam.NewFromConfig(cfg),
// 	}
// }

// // RunCheckPolicies checks if the IAM users have the correct policies attached
// // 03.01.01 Account Management
// func (c *IAMCheck) RunCheckPolicies() error {

// 	listUsersOutput, err := c.IAMClient.ListUsers(context.TODO(), &iam.ListUsersInput{})
// 	if err != nil {
// 		return LogAndReturnError("unable to list users", err)
// 	}

// 	usersFromConfig := config.AppConfig.AWS.Users

// 	var nonConformingUsers []string

// 	for _, awsUser := range listUsersOutput.Users {
// 		log.Printf("=======> Check for AWS user: %s\n", *awsUser.UserName)

// 		attachedPoliciesOutput, err := c.IAMClient.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
// 			UserName: awsUser.UserName,
// 		})
// 		if err != nil {
// 			return LogAndReturnError(fmt.Sprintf("unable to list attached policies for user %s", *awsUser.UserName), err)
// 		}

// 		var configUser *config.User
// 		for i, user := range usersFromConfig {
// 			if user.Name == *awsUser.UserName {
// 				configUser = &usersFromConfig[i]
// 				break
// 			}
// 		}

// 		if configUser == nil {
// 			log.Printf("User %s not found in config file\n", *awsUser.UserName)
// 			nonConformingUsers = append(nonConformingUsers, *awsUser.UserName)
// 			continue
// 		}

// 		if len(configUser.Policies) == 0 {
// 			log.Printf("ERROR: User %s has no policies defined in the configuration file\n", *awsUser.UserName)
// 			nonConformingUsers = append(nonConformingUsers, configUser.Name)
// 			continue
// 		}

// 		for _, awsPolicy := range attachedPoliciesOutput.AttachedPolicies {
// 			log.Printf("=======> User %s has the policy: %s\n", *awsUser.UserName, *awsPolicy.PolicyName)

// 			if !ContainsString(configUser.Policies, *awsPolicy.PolicyName) {
// 				log.Printf("ERROR: Policy %s assigned to user %s is not defined in the configuration file\n", *awsPolicy.PolicyName, *awsUser.UserName)
// 				nonConformingUsers = append(nonConformingUsers, configUser.Name)
// 				continue
// 			}
// 		}

// 		for _, configPolicy := range configUser.Policies {
// 			found := false
// 			for _, awsPolicy := range attachedPoliciesOutput.AttachedPolicies {
// 				if configPolicy == *awsPolicy.PolicyName {
// 					found = true
// 					break
// 				}
// 			}
// 			if !found {
// 				log.Printf("ERROR: Policy %s defined in the configuration file is not assigned to user %s\n", configPolicy, *awsUser.UserName)
// 				nonConformingUsers = append(nonConformingUsers, configUser.Name)
// 			}
// 		}
// 	}

// 	// If there are non-conforming users, return an error
// 	if len(nonConformingUsers) > 0 {
// 		return fmt.Errorf("non-conforming users found: %v", nonConformingUsers)
// 	}

// 	return nil
// }

// // RunCheckAcceptedPolicies checks if the accepted policies are present on AWS
// // 03.01.02 Access Enforcement
// func (c *IAMCheck) RunCheckAcceptedPolicies() error {

// 	// Load the accepted policies from the configuration file
// 	acceptedPolicies := config.AppConfig.AWS.AcceptedPolicies

// 	// List the managed policies on AWS
// 	listPoliciesOutput, err := c.IAMClient.ListPolicies(context.TODO(), &iam.ListPoliciesInput{})
// 	if err != nil {
// 		return fmt.Errorf("unable to list policies on AWS: %v", err)
// 	}

// 	// Log to verify the policies actually present on AWS
// 	log.Printf("INFO: Policies found on AWS:")
// 	for _, policy := range listPoliciesOutput.Policies {
// 		log.Printf("Policy found: %s/d", *policy.PolicyName)
// 	}

// 	policiesOnAWS := MapAWSManagedPolicies(listPoliciesOutput.Policies)

// 	// Compare the accepted policies with those actually present on AWS
// 	for _, acceptedPolicy := range acceptedPolicies {
// 		if _, exists := policiesOnAWS[acceptedPolicy]; !exists {
// 			log.Printf("ERROR: Accepted policy %s not found on AWS", acceptedPolicy)
// 			return fmt.Errorf("accepted policy %s not found on AWS", acceptedPolicy)
// 		}
// 	}

// 	log.Println("INFO: All accepted policies are compliant on AWS")
// 	return nil
// }

// // RunSecurityGroupCheck performs the compliance check on security groups
// func RunSecurityGroupCheck(securityGroupsFromConfig []config.SecurityGroup, securityGroupsFromAWS []ec2types.SecurityGroup) error {
// 	isCompliant := true

// 	sgMap := make(map[string]config.SecurityGroup)
// 	for _, sg := range securityGroupsFromConfig {
// 		sgMap[sg.Name] = sg
// 	}

// 	for _, awsSG := range securityGroupsFromAWS {
// 		log.Printf("Check for security group: %s\n", *awsSG.GroupName)

// 		configSG, ok := sgMap[*awsSG.GroupName]
// 		if !ok {
// 			// If not found, mark the security group as non-compliant
// 			log.Printf("ERROR: Security group %s not found in the configuration file\n", *awsSG.GroupName)
// 			isCompliant = false
// 			continue
// 		}

// 		// Check ingress ports
// 		if awsSG.IpPermissions != nil {
// 			for _, ingress := range awsSG.IpPermissions {
// 				if ingress.FromPort != nil && !Contains(configSG.AllowedIngressPorts, int(*ingress.FromPort)) {
// 					log.Printf("Ingress port %d not allowed for group %s\n", *ingress.FromPort, *awsSG.GroupName)
// 					isCompliant = false
// 				}
// 			}
// 		}

// 		// Check egress ports
// 		if awsSG.IpPermissionsEgress != nil {
// 			for _, egress := range awsSG.IpPermissionsEgress {
// 				if egress.FromPort != nil && !Contains(configSG.AllowedEgressPorts, int(*egress.FromPort)) {
// 					log.Printf("Egress port %d not allowed for group %s\n", *egress.FromPort, *awsSG.GroupName)
// 					isCompliant = false
// 				}
// 			}
// 		}
// 	}

// 	// If there are non-conformities, return an error
// 	if !isCompliant {
// 		return fmt.Errorf("one or more security groups are not compliant")
// 	}

// 	// Return nil if all checks are compliant
// 	return nil
// }

// // RunS3BucketCheck performs the compliance check on S3 buckets
// func (c *IAMCheck) RunS3BucketCheck() error {
// 	listBucketsOutput, err := c.S3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
// 	if err != nil {
// 		return LogAndReturnError("unable to list S3 buckets", err)
// 	}

// 	s3BucketsFromConfig := config.AppConfig.AWS.S3Buckets

// 	return CheckS3BucketsCompliance(c.S3Client, s3BucketsFromConfig, listBucketsOutput.Buckets)
// }

// // RunCheckCUIFlow performs the compliance checks required for NIST SP 800-171 3.1.3
// func (c *IAMCheck) RunCheckCUIFlow() error {

// 	securityGroupsFromConfig := config.AppConfig.AWS.SecurityGroups

// 	// List the security groups from AWS
// 	describeSGOutput, err := c.EC2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
// 	if err != nil {
// 		return LogAndReturnError("unable to list security groups", err)
// 	}

// 	// Pass the loaded data to the RunSecurityGroupCheck function
// 	if err := RunSecurityGroupCheck(securityGroupsFromConfig, describeSGOutput.SecurityGroups); err != nil {
// 		return LogAndReturnError("error during security group check", err)
// 	}

// 	log.Println("===== Security group check completed =====")

// 	if err := c.RunS3BucketCheck(); err != nil {
// 		return LogAndReturnError("error during S3 bucket check", err)
// 	}
// 	log.Println("===== S3 bucket check completed =====")

// 	return nil
// }

// // RunCheckSeparateDuties performs the check for the NIST 3.1.4 requirement
// func (c *IAMCheck) RunCheckSeparateDuties() error {
// 	criticalRoles := config.AppConfig.AWS.CriticalRoles

// 	listRolesOutput, err := c.IAMClient.ListRoles(context.TODO(), &iam.ListRolesInput{})
// 	if err != nil {
// 		return LogAndReturnError("unable to list IAM roles on AWS", err)
// 	}

// 	roleFunctionMap := MapRolesToFunctions(listRolesOutput.Roles, c.IAMClient)

// 	for _, criticalRole := range criticalRoles {
// 		if err := VerifyCriticalRoleCompliance(criticalRole, roleFunctionMap); err != nil {
// 			return err
// 		}
// 	}

// 	log.Println("INFO: Separation of duties check successfully completed.")
// 	return nil
// }

// // RunPrivilegeCheck performs the check for privileges 3.1.5
// func (c *IAMCheck) RunPrivilegeCheck() error {
// 	// Load the users and their policies from the configuration
// 	usersFromConfig := config.AppConfig.AWS.Users

// 	// Check privileges and security functions for each user
// 	for _, user := range usersFromConfig {
// 		log.Printf("Checking privileges for user: %s\n", user.Name)

// 		// Check that each security function corresponds to an assigned policy
// 		for _, sf := range user.SecurityFunctions {
// 			log.Printf("Checking security function %s for user %s\n", sf, user.Name)

// 			// Variable to determine if a corresponding policy was found
// 			found := false

// 			// Check if there is a policy that covers the security function
// 			for _, policy := range user.Policies {
// 				log.Printf("Checking policy %s for security function %s\n", policy, sf)

// 				if policy == sf {
// 					found = true
// 					break
// 				}
// 			}

// 			// If no corresponding policy is found for the security function, log the error
// 			if !found {
// 				log.Printf("ERROR: Security function %s for user %s is not covered by any policy\n", sf, user.Name)
// 				return fmt.Errorf("security functions not compliant for user %s", user.Name)
// 			}
// 		}

// 	}

// 	return nil
// }

// // RunPrivilegeAccountCheck performs the check for the NIST 3.1.6 requirement
// func (c *IAMCheck) RunPrivilegeAccountCheck() error {
// 	usersFromConfig := config.AppConfig.AWS.Users

// 	for _, user := range usersFromConfig {
// 		log.Printf("Checking privileges for user: %s\n", user.Name)

// 		// If the user is not privileged but has security functions
// 		if !user.IsPrivileged && len(user.SecurityFunctions) > 0 {
// 			for _, sf := range user.SecurityFunctions {
// 				log.Printf("ERROR: User %s is not privileged but has access to security function: %s\n", user.Name, sf)
// 			}
// 			return fmt.Errorf("non-privileged user %s with access to security functions", user.Name)
// 		}

// 		// If the user is privileged but has no security functions
// 		if user.IsPrivileged && len(user.SecurityFunctions) == 0 {
// 			log.Printf("ERROR: Privileged user %s has no assigned security functions\n", user.Name)
// 			return fmt.Errorf("privileged user %s without security functions", user.Name)
// 		}

// 		// Check that the policies match the security functions
// 		for _, sf := range user.SecurityFunctions {
// 			if !ContainsString(user.Policies, sf) {
// 				log.Printf("ERROR: Policy %s for user %s does not match the security function %s\n", user.Policies, user.Name, sf)
// 				return fmt.Errorf("security functions not compliant for user %s", user.Name)
// 			}
// 		}
// 	}

// 	log.Println("Privilege check successfully completed")
// 	return nil
// }

// // RunPrivilegedFunctionCheck performs the check for the NIST 3.1.7 requirement
// func (c *IAMCheck) RunPrivilegedFunctionCheck() error {

// 	for _, user := range config.AppConfig.AWS.Users {
// 		log.Printf("Checking privileges for user: %s\n", user.Name)

// 		// Check if a non-privileged user has access to privileged functions
// 		if !user.IsPrivileged && len(user.SecurityFunctions) > 0 {
// 			for _, sf := range user.SecurityFunctions {
// 				// If the non-privileged user has a security function, log the error
// 				log.Printf("ERROR: Non-privileged user %s has access to security function: %s\n", user.Name, sf)
// 				return fmt.Errorf("non-privileged user %s with access to security functions: %s", user.Name, sf)
// 			}
// 		}
// 	}

// 	// All checks passed
// 	log.Println("Privileged function check successfully completed.")
// 	return nil
// }

// // LoginAttempt represents a login attempt
// type LoginAttempt struct {
// 	Username       string
// 	AttemptTime    time.Time
// 	IsSuccessful   bool
// 	FailedAttempts int
// 	IsLocked       bool
// 	LockoutTime    time.Time
// }

// var failedAttempts = map[string]*LoginAttempt{}

// // RunLoginAttemptCheck checks failed login attempts and applies defined actions
// func (c *IAMCheck) RunLoginAttemptCheck(user string, isSuccess bool, loginPolicy config.LoginPolicy) error {
// 	now := time.Now()

// 	// Check if the user has already made failed login attempts
// 	if _, exists := failedAttempts[user]; !exists {
// 		failedAttempts[user] = &LoginAttempt{
// 			Username:       user,
// 			AttemptTime:    now,
// 			IsSuccessful:   isSuccess,
// 			FailedAttempts: 0,
// 			IsLocked:       false,
// 		}
// 	}

// 	loginAttempt := failedAttempts[user]

// 	// If the account is locked, check if it should be unlocked
// 	if loginAttempt.IsLocked {
// 		if now.Sub(loginAttempt.LockoutTime) > time.Duration(loginPolicy.LockoutDurationMinutes)*time.Minute {
// 			// Unlock the account after the lockout period
// 			loginAttempt.IsLocked = false
// 			loginAttempt.FailedAttempts = 0
// 			log.Printf("Account %s automatically unlocked\n", user)
// 		} else {
// 			// The account is still locked
// 			log.Printf("Account %s is locked until %s\n", user, loginAttempt.LockoutTime.Add(time.Duration(loginPolicy.LockoutDurationMinutes)*time.Minute))
// 			return fmt.Errorf("account %s locked", user)
// 		}
// 	}

// 	// If the login attempt failed, increment the count
// 	if !isSuccess {
// 		loginAttempt.FailedAttempts++
// 		log.Printf("Failed login attempt for user %s. Total failed attempts: %d\n", user, loginAttempt.FailedAttempts)

// 		// Check if the maximum number of attempts has been exceeded
// 		if loginAttempt.FailedAttempts >= loginPolicy.MaxUnsuccessfulAttempts {
// 			// Apply the lockout action
// 			loginAttempt.IsLocked = true
// 			loginAttempt.LockoutTime = now

// 			// Check that `ActionOnLockout` is specified and apply the action
// 			switch loginPolicy.ActionOnLockout {
// 			case "lock_account":
// 				log.Printf("Account %s locked for %d minutes\n", user, loginPolicy.LockoutDurationMinutes)
// 			case "notify_admin":
// 				log.Printf("Administrator notified for account lockout %s\n", user)
// 			default:
// 				log.Printf("Unknown action for account lockout %s: %s\n", user, loginPolicy.ActionOnLockout)
// 				return fmt.Errorf("unknown lockout action: %s", loginPolicy.ActionOnLockout)
// 			}
// 			return fmt.Errorf("maximum failed login attempts reached for user %s", user)
// 		}
// 	} else {
// 		// If the login was successful, reset the failed attempts count
// 		loginAttempt.FailedAttempts = 0
// 	}

// 	return nil
// }

// // RunSessionTimeoutCheck performs the check for the NIST 3.1.10 requirement
// func (c *IAMCheck) RunSessionTimeoutCheck(cfg aws.Config) error {
// 	ssmClient := ssm.NewFromConfig(cfg)

// 	// Log: Start checking active sessions
// 	log.Println("Starting check of active sessions...")

// 	// List the active sessions
// 	listSessionsInput := &ssm.DescribeSessionsInput{
// 		State: "Active",
// 	}

// 	listSessionsOutput, err := ssmClient.DescribeSessions(context.TODO(), listSessionsInput)
// 	if err != nil {
// 		return fmt.Errorf("unable to list active sessions: %v", err)
// 	}

// 	// Log: Number of active sessions found
// 	log.Printf("Number of active sessions found: %d\n", len(listSessionsOutput.Sessions))

// 	// Check the inactivity of each session and terminate if necessary
// 	for _, session := range listSessionsOutput.Sessions {
// 		inactivityDuration := time.Since(*session.StartDate)

// 		// Log: Inactivity duration for the current session
// 		log.Printf("Session ID: %s, Inactivity: %v\n", *session.SessionId, inactivityDuration)

// 		// Inactivity timeout of 30 minutes
// 		if inactivityDuration > time.Duration(30)*time.Minute {
// 			terminateSessionInput := &ssm.TerminateSessionInput{
// 				SessionId: session.SessionId,
// 			}

// 			// Log: Attempt to terminate the session due to inactivity
// 			log.Printf("Attempting to terminate session %s due to inactivity...\n", *session.SessionId)

// 			_, err := ssmClient.TerminateSession(context.TODO(), terminateSessionInput)
// 			if err != nil {
// 				return fmt.Errorf("unable to terminate session %s: %v", *session.SessionId, err)
// 			}

// 			// Log: Confirm the session was terminated
// 			log.Printf("Session %s successfully terminated due to inactivity\n", *session.SessionId)
// 		} else {
// 			// Log: Session still active and not terminated
// 			log.Printf("Session %s still active and not terminated due to inactivity\n", *session.SessionId)
// 		}
// 	}

// 	// Log: End of active session check
// 	log.Println("Active session check completed.")

// 	return nil
// }

// func (c *IAMCheck) RunInactivitySessionCheck(cfg aws.Config, username string) error {
// 	iamClient := iam.NewFromConfig(cfg)

// 	log.Printf("Starting session policy check for IAM user %s...\n", username)

// 	listPoliciesInput := &iam.ListAttachedUserPoliciesInput{
// 		UserName: &username,
// 	}
// 	listPoliciesOutput, err := iamClient.ListAttachedUserPolicies(context.TODO(), listPoliciesInput)
// 	if err != nil {
// 		return fmt.Errorf("unable to list policies for user %s: %v", username, err)
// 	}

// 	found := false
// 	for _, policy := range listPoliciesOutput.AttachedPolicies {
// 		if *policy.PolicyName == "ForceSessionTimeout" {
// 			found = true
// 			break
// 		}
// 	}

// 	if !found {
// 		log.Printf("ERROR: ForceSessionTimeout policy is not attached to user %s\n", username)
// 		return fmt.Errorf("ForceSessionTimeout policy not found for user %s", username)
// 	}

// 	log.Printf("ForceSessionTimeout policy found for user %s\n", username)
// 	log.Println("IAM session policy check completed.")

// 	return nil
// }

// // RunRemoteMonitoringCheck checks whether VPC Flow Logs and CloudTrail are enabled
// // NIST SP 800-171 requirement 3.1.20
// func (c *IAMCheck) RunRemoteMonitoringCheck(cfg aws.Config) error {
// 	cloudTrailClient := cloudtrail.NewFromConfig(cfg)

// 	log.Println("Checking if VPC Flow Logs are enabled...")

// 	describeFlowLogsInput := &ec2.DescribeFlowLogsInput{}
// 	flowLogsOutput, err := c.EC2Client.DescribeFlowLogs(context.TODO(), describeFlowLogsInput)
// 	if err != nil {
// 		errorMessage := fmt.Sprintf("Error retrieving VPC Flow Logs: %v", err)
// 		log.Println(errorMessage)
// 		return fmt.Errorf(errorMessage)
// 	}

// 	log.Printf("Number of VPC Flow Logs found: %d\n", len(flowLogsOutput.FlowLogs))

// 	if len(flowLogsOutput.FlowLogs) == 0 {
// 		errorMessage := "ERROR: No VPC Flow Logs enabled: non-compliant"
// 		log.Println(errorMessage)
// 		return fmt.Errorf(errorMessage)
// 	}

// 	log.Println("SUCCESS: VPC Flow Logs are enabled and monitoring traffic.")

// 	trailStatusInput := &cloudtrail.GetTrailStatusInput{
// 		Name: aws.String("management-events"), // TODO - ask user
// 	}

// 	trailStatusOutput, err := cloudTrailClient.GetTrailStatus(context.TODO(), trailStatusInput)
// 	if err != nil {
// 		errorMessage := fmt.Sprintf("Error retrieving CloudTrail status: %v", err)
// 		fmt.Println(errorMessage)
// 		return fmt.Errorf(errorMessage)
// 	}

// 	// Log: CloudTrail status
// 	if !*trailStatusOutput.IsLogging {
// 		errorMessage := "ERROR: CloudTrail is not enabled: non-compliant"
// 		fmt.Println(errorMessage)
// 		return fmt.Errorf(errorMessage)
// 	}

// 	log.Println("SUCCESS: CloudTrail is enabled and monitoring remote connections.")

// 	// Log: End of check
// 	log.Println("Remote connection monitoring check successfully completed.")

// 	return nil
// }
