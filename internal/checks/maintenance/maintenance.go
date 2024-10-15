package maintenance

import (
	"cloud_compliance_checker/config"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// RunMonitorCheck verifies AWS assets against the configuration loaded from AWS config
// 03.07.4
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

// CheckNonLocalMaintenanceCompliance initiates the check for nonlocal maintenance compliance
// 03.07.5
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

// CheckMaintenanceAuthorization verifies that all users listed in config have the required tags
// 03.07.6
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
