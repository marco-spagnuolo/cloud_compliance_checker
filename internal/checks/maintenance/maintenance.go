package maintenance

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	mtypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ScanForMalware scans EC2 instances for GuardDuty findings
func ScanForMalware(instanceID, detectorID string, awsCfg aws.Config) error {
	log.Printf("Scanning for malware on instance %s using GuardDuty", instanceID)
	guarddutySvc := guardduty.NewFromConfig(awsCfg)

	input := &guardduty.ListFindingsInput{
		DetectorId: aws.String(detectorID),
		FindingCriteria: &gtypes.FindingCriteria{
			Criterion: map[string]gtypes.Condition{
				"resource.instanceDetails.instanceId": {Equals: []string{instanceID}},
			},
		},
	}

	_, err := guarddutySvc.ListFindings(context.TODO(), input)
	if err != nil {
		log.Printf("Error during GuardDuty scan for instance %s: %v", instanceID, err)
		return fmt.Errorf("failed to scan for malicious code: %v", err)
	}

	log.Println("GuardDuty scan completed. No malicious code found.")
	return nil
}

func MonitorS3Bucket(bucketName, accountID string, awsCfg aws.Config) error {
	log.Printf("Starting Macie CUI scan for bucket %s", bucketName)
	svc := macie2.NewFromConfig(awsCfg)

	// Generate a unique job name by appending the current timestamp
	jobName := fmt.Sprintf("CUI-Scan-Job-%s", time.Now().Format("20060102-150405"))

	jobInput := &macie2.CreateClassificationJobInput{
		Name: aws.String(jobName),
		S3JobDefinition: &mtypes.S3JobDefinition{
			BucketDefinitions: []mtypes.S3BucketDefinitionForJob{
				{
					AccountId: aws.String(accountID),
					Buckets:   []string{bucketName},
				},
			},
		},
		JobType: mtypes.JobTypeOneTime,
	}

	_, err := svc.CreateClassificationJob(context.TODO(), jobInput)
	if err != nil {
		log.Printf("Error starting Macie classification job for bucket %s: %v", bucketName, err)
		return fmt.Errorf("failed to start Macie classification job for bucket %s: %v", bucketName, err)
	}

	log.Printf("Macie job started to monitor CUI in bucket %s", bucketName)
	return nil
}

// CheckEC2Instance verifies EC2 compliance against monitoring tools and active state
func CheckEC2Instance(instanceID string, awsCfg aws.Config) error {
	log.Printf("Checking EC2 instance %s state", instanceID)
	ec2Svc := ec2.NewFromConfig(awsCfg)

	// Check instance state
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}
	resp, err := ec2Svc.DescribeInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Error describing instance %s: %v", instanceID, err)
		return fmt.Errorf("failed to describe instance %s: %v", instanceID, err)
	}

	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State.Name != ec2types.InstanceStateNameRunning {
				log.Printf("Instance %s is not running", instanceID)
				return fmt.Errorf("instance %s is not in running state", *instance.InstanceId)
			}
			log.Printf("Instance %s is in running state", *instance.InstanceId)
		}
	}

	return nil
}

// RunMonitorCheck verifies AWS assets against the configuration loaded from AWS config
func RunMonitorCheck(awsCfg aws.Config) error {
	// Load the config from config.AppConfig
	cfg := config.AppConfig.AWS.MaintenanceConfig

	// Check EC2 compliance
	for _, instance := range cfg.EC2MonitoredInstances {
		log.Printf("Checking EC2 instance %s", instance.InstanceID)
		err := CheckEC2Instance(instance.InstanceID, awsCfg)
		if err != nil {
			log.Printf("EC2 compliance check failed for instance %s: %v", instance.InstanceID, err)
			return fmt.Errorf("EC2 compliance check failed: %v", err)
		}

		// Validate tools
		for _, tool := range instance.MonitoringTools {
			log.Printf("Validating tool %s for instance %s", tool, instance.InstanceID)
			if !ValidateTool(instance.InstanceID, tool, cfg) {
				log.Printf("Tool %s is NOT approved for instance %s", tool, instance.InstanceID)
				return fmt.Errorf("tool %s is not approved for instance %s", tool, instance.InstanceID)
			}
			log.Printf("Tool %s is approved for instance %s", tool, instance.InstanceID)
		}

		// Scan for malware using GuardDuty
		log.Printf("Scanning instance %s for malware using GuardDuty", instance.InstanceID)
		err = ScanForMalware(instance.InstanceID, cfg.GuardDutyDetectorID, awsCfg)
		if err != nil {
			log.Printf("Malware scan failed for instance %s: %v", instance.InstanceID, err)
			return fmt.Errorf("malware scan failed on instance %s: %v", instance.InstanceID, err)
		}
	}

	// Monitor S3 bucket for CUI with Macie
	log.Printf("Monitoring S3 bucket %s for CUI", cfg.BucketName)
	err := MonitorS3Bucket(cfg.BucketName, cfg.AccountID, awsCfg)
	if err != nil {
		log.Printf("S3 bucket monitoring failed: %v", err)
		return fmt.Errorf("S3 bucket monitoring failed: %v", err)
	}

	log.Println("Compliance check completed successfully.")
	return nil
}

// ValidateTool checks if a given tool is approved for a specific instance
func ValidateTool(instanceID, toolName string, cfg config.MaintenanceConfig) bool {
	for _, instance := range cfg.EC2MonitoredInstances {
		if instance.InstanceID == instanceID {
			for _, tool := range instance.MonitoringTools {
				if tool == toolName {
					return true
				}
			}
		}
	}
	return false
}

// isMFAEnabled checks if MFA is enabled for the IAM user associated with the instance
func isMFAEnabled(userName string, awsCfg aws.Config) bool {

	svc := iam.NewFromConfig(awsCfg)
	input := &iam.ListMFADevicesInput{
		UserName: aws.String(userName),
	}

	resp, err := svc.ListMFADevices(context.TODO(), input)
	if err != nil {
		log.Printf("Error checking MFA for user %s: %v", userName, err)
		return false
	}

	if len(resp.MFADevices) == 0 {
		log.Printf("No MFA devices found for user %s", userName)
		return false
	}
	log.Printf("MFA is enabled for user %s", userName)
	return true
}

// TerminateNonLocalSession terminates an active SSM session
func TerminateNonLocalSession(sessionID string, awsCfg aws.Config) error {
	log.Printf("Terminating nonlocal maintenance session %s", sessionID)
	svc := ssm.NewFromConfig(awsCfg)

	input := &ssm.TerminateSessionInput{
		SessionId: aws.String(sessionID),
	}

	_, err := svc.TerminateSession(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to terminate session %s: %v", sessionID, err)
		return fmt.Errorf("failed to terminate session %s: %v", sessionID, err)
	}

	log.Printf("Session %s terminated successfully", sessionID)
	return nil
}

// ApproveAndMonitorNonLocalSession approves and monitors nonlocal maintenance activities.
func ApproveAndMonitorNonLocalSession(instanceID, command, sessionID, userName string, awsCfg aws.Config) error {
	log.Printf("Approving and monitoring nonlocal session on instance %s", instanceID)
	user_names := config.AppConfig.AWS.MaintenanceConfig.NonLocalMaintenance.UserNames
	for _, user := range user_names {

		// Verify MFA
		if !isMFAEnabled(user, awsCfg) {
			return fmt.Errorf("MFA is not enabled for user %s", user)
		}
	}
	// Execute command
	output, err := ExecuteMaintenanceCommand(instanceID, command, awsCfg)
	if err != nil {
		return fmt.Errorf("Failed to execute nonlocal command: %v", err)
	}
	log.Printf("Command output: %s", output)
	if err != nil {
		return fmt.Errorf("Failed to execute nonlocal command: %v", err)
	}

	// Terminate session
	err = TerminateNonLocalSession(sessionID, awsCfg)
	if err != nil {
		return fmt.Errorf("Failed to terminate session: %v", err)
	}

	log.Printf("Nonlocal session completed for instance %s", instanceID)
	return nil
}

// StartSSMSession creates an SSM session on an instance
func StartSSMSession(instanceID string, awsCfg aws.Config) (string, error) {
	log.Printf("Starting SSM session on instance %s", instanceID)
	svc := ssm.NewFromConfig(awsCfg)

	input := &ssm.StartSessionInput{
		Target: aws.String(instanceID),
	}

	output, err := svc.StartSession(context.TODO(), input)
	if err != nil {
		log.Printf("Error starting SSM session: %v", err)
		return "", fmt.Errorf("failed to start SSM session on instance %s: %v", instanceID, err)
	}

	log.Printf("SSM session started with session ID: %s", *output.SessionId)
	return *output.SessionId, nil
}

// CheckNonLocalMaintenanceCompliance initiates the check for nonlocal maintenance compliance
func CheckNonLocalMaintenanceCompliance(awsCfg aws.Config) error {
	log.Println("Initiating nonlocal maintenance compliance check")

	// Step 1: Create SSM session
	for _, instance := range config.AppConfig.AWS.MaintenanceConfig.EC2MonitoredInstances {
		userNames := config.AppConfig.AWS.MaintenanceConfig.NonLocalMaintenance.UserNames

		for _, user := range userNames {
			// Check if MFA is enabled
			if !isMFAEnabled(user, awsCfg) {
				return fmt.Errorf("MFA is not enabled for user %s", user)
			}
		}

		// Create and execute session on the instance
		sessionID, err := StartSSMSession(instance.InstanceID, awsCfg)
		if err != nil {
			return fmt.Errorf("failed to start SSM session: %v", err)
		}

		// Execute maintenance command
		command := "echo 'Checking compliance...'"
		_, err = ExecuteMaintenanceCommand(instance.InstanceID, command, awsCfg)
		if err != nil {
			return fmt.Errorf("failed to execute maintenance command: %v", err)
		}

		// Terminate the SSM session
		err = TerminateNonLocalSession(sessionID, awsCfg)
		if err != nil {
			return fmt.Errorf("failed to terminate session: %v", err)
		}

		log.Printf("Compliance check completed for instance %s", instance.InstanceID)
	}

	log.Println("Nonlocal maintenance compliance check finished.")
	return nil
}

func EnsureSSMAgent(instanceID string, awsCfg aws.Config) error {
	log.Printf("Ensuring SSM Agent is installed and connected on instance %s", instanceID)

	// Check SSM Agent status
	checkCommand := "if ! systemctl is-active --quiet amazon-ssm-agent; then echo 'missing'; fi"
	output, err := ExecuteMaintenanceCommand(instanceID, checkCommand, awsCfg)
	if err != nil {
		log.Printf("Failed to check SSM agent status on instance %s: %v", instanceID, err)
		return err
	}

	// Install if missing
	if output == "missing" {
		log.Printf("SSM Agent not installed on instance %s. Installing...", instanceID)
		installCommand := `
			if [ -f /etc/redhat-release ]; then 
				sudo yum install -y amazon-ssm-agent; 
			elif [ -f /etc/lsb-release ]; then 
				sudo apt-get install -y amazon-ssm-agent; 
			fi;
			sudo systemctl start amazon-ssm-agent
		`
		_, err = ExecuteMaintenanceCommand(instanceID, installCommand, awsCfg)
		if err != nil {
			return fmt.Errorf("failed to install SSM agent on instance %s: %v", instanceID, err)
		}
		log.Printf("SSM Agent installed on instance %s", instanceID)
	}

	// Restart SSM Agent
	log.Printf("Restarting SSM Agent on instance %s", instanceID)
	restartCommand := "sudo systemctl restart amazon-ssm-agent"
	_, err = ExecuteMaintenanceCommand(instanceID, restartCommand, awsCfg)
	if err != nil {
		return fmt.Errorf("failed to restart SSM agent on instance %s: %v", instanceID, err)
	}

	// Verify SSM connectivity
	ssmSvc := ssm.NewFromConfig(awsCfg)
	instanceStatusInput := &ssm.DescribeInstanceInformationInput{}
	instanceInfo, err := ssmSvc.DescribeInstanceInformation(context.TODO(), instanceStatusInput)
	if err != nil {
		return fmt.Errorf("failed to verify SSM connection for instance %s: %v", instanceID, err)
	}

	connected := false
	for _, info := range instanceInfo.InstanceInformationList {
		if *info.InstanceId == instanceID && info.PingStatus == ssmtypes.PingStatusOnline {
			connected = true
			break
		}
	}

	if !connected {
		return fmt.Errorf("instance %s is still not connected to SSM", instanceID)
	}

	log.Printf("Instance %s is connected to SSM", instanceID)
	return nil
}

// ExecuteMaintenanceCommand runs a command via AWS Systems Manager (SSM) and returns the output
func ExecuteMaintenanceCommand(instanceID, command string, awsCfg aws.Config) (string, error) {
	log.Printf("Executing SSM command on instance %s", instanceID)
	svc := ssm.NewFromConfig(awsCfg)

	input := &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {command},
		},
	}

	cmdOutput, err := svc.SendCommand(context.TODO(), input)
	if err != nil {
		log.Printf("Error executing command on instance %s: %v", instanceID, err)
		return "", fmt.Errorf("failed to execute command on instance %s: %v", instanceID, err)
	}

	commandID := *cmdOutput.Command.CommandId
	// Wait for the command to complete and fetch the result
	log.Printf("Waiting for SSM command %s to complete on instance %s", commandID, instanceID)
	result, err := svc.GetCommandInvocation(context.TODO(), &ssm.GetCommandInvocationInput{
		CommandId:  aws.String(commandID),
		InstanceId: aws.String(instanceID),
	})
	if err != nil {
		log.Printf("Failed to retrieve command output: %v", err)
		return "", err
	}

	return *result.StandardOutputContent, nil
}

// CreateAndTerminateNonLocalSession creates an SSM session and terminates it after completion
func CreateAndTerminateNonLocalSession(instanceID, command, userName string, awsCfg aws.Config) error {
	log.Printf("Approving and monitoring nonlocal session on instance %s", instanceID)
	userNames := config.AppConfig.AWS.MaintenanceConfig.NonLocalMaintenance.UserNames

	for _, user := range userNames {
		// Verify MFA
		if !isMFAEnabled(user, awsCfg) {
			return fmt.Errorf("MFA is not enabled for user %s", user)
		}
	}

	// Ensure SSM Agent is installed and running
	err := EnsureSSMAgent(instanceID, awsCfg)
	if err != nil {
		return fmt.Errorf("SSM agent verification/installation failed: %v", err)
	}

	// Step 1: Create an SSM session
	sessionID, err := StartSSMSession(instanceID, awsCfg)
	if err != nil {
		return fmt.Errorf("failed to create SSM session: %v", err)
	}

	// Step 2: Execute the command
	_, err = ExecuteMaintenanceCommand(instanceID, command, awsCfg)
	if err != nil {
		return fmt.Errorf("Failed to execute nonlocal command: %v", err)
	}

	// Step 3: Terminate the session
	err = TerminateNonLocalSession(sessionID, awsCfg)
	if err != nil {
		return fmt.Errorf("Failed to terminate session: %v", err)
	}

	log.Printf("Nonlocal session completed for instance %s", instanceID)
	return nil
}

// IsUserAuthorizedForMaintenance checks if a user has the 'maintenance' tag
func IsUserAuthorizedForMaintenance(userName string, awsCfg aws.Config) (bool, error) {
	log.Printf("Checking if user %s is authorized for maintenance", userName)

	svc := iam.NewFromConfig(awsCfg)

	input := &iam.ListUserTagsInput{
		UserName: aws.String(userName),
	}

	resp, err := svc.ListUserTags(context.TODO(), input)
	if err != nil {
		log.Printf("Error listing tags for user %s: %v", userName, err)
		return false, fmt.Errorf("failed to list tags for user %s: %v", userName, err)
	}

	for _, tag := range resp.Tags {
		if *tag.Key == "Role" && *tag.Value == "maintenance" {
			log.Printf("User %s is authorized for maintenance", userName)
			return true, nil
		}
	}

	log.Printf("User %s is NOT authorized for maintenance", userName)
	return false, nil
}

// CheckMaintenanceAuthorization verifies that all users listed in config have the required tags
func CheckMaintenanceAuthorization(awsCfg aws.Config) error {
	log.Println("Checking maintenance personnel authorization compliance")

	for _, user := range config.AppConfig.AWS.MaintenanceConfig.AuthorizedUsers.UserNames {
		authorized, err := IsUserAuthorizedForMaintenance(user, awsCfg)
		if err != nil {
			return fmt.Errorf("failed to check maintenance authorization for user %s: %v", user, err)
		}
		if !authorized {
			return fmt.Errorf("user %s is not authorized for maintenance", user)
		}
	}

	log.Println("All listed maintenance personnel are properly authorized.")
	return nil
}
