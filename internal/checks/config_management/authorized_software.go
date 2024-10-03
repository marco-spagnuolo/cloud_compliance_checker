package config_management

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// GetRunningSoftware retrieves the installed or running software on an EC2 instance using AWS SSM.
func GetRunningSoftware(cfg aws.Config, instanceID string) ([]string, error) {
	ssmClient := ssm.NewFromConfig(cfg)

	// Usa il comando "rpm -qa" per sistemi Red Hat-based come Amazon Linux
	command := "rpm -qa" // Questo funziona per Amazon Linux e altre distribuzioni basate su Red Hat

	input := &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {command},
		},
	}

	// Invia il comando all'istanza EC2
	sendCmdOutput, err := ssmClient.SendCommand(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("error sending command to instance %s: %v", instanceID, err)
	}

	// Recupera l'ID del comando
	commandID := *sendCmdOutput.Command.CommandId

	// Attendi che il comando sia completato e recupera il risultato
	time.Sleep(5 * time.Second)

	// Ottieni l'output del comando
	getCmdInput := &ssm.GetCommandInvocationInput{
		CommandId:  &commandID,
		InstanceId: &instanceID,
	}

	cmdOutput, err := ssmClient.GetCommandInvocation(context.TODO(), getCmdInput)
	if err != nil {
		return nil, fmt.Errorf("error retrieving command output from instance %s: %v", instanceID, err)
	}

	// Analizza e restituisci la lista dei software
	if cmdOutput.Status == types.CommandInvocationStatusSuccess {
		output := cmdOutput.StandardOutputContent
		softwareList := strings.Split(*output, "\n")
		return softwareList, nil
	}

	return nil, fmt.Errorf("command execution failed on instance %s: %v", instanceID, cmdOutput.StatusDetails)
}

// CheckAuthorizedSoftware checks the running software on EC2 instances against the configuration's authorized software list.
func CheckAuthorizedSoftware(cfg aws.Config, awsConfig *config.AWSConfig) error {
	// Retrieve EC2 instances from AWS using GetEC2Instances (this is a function that retrieves running EC2 instances)
	ec2Instances, err := GetEC2Instances(cfg)
	if err != nil {
		return fmt.Errorf("error retrieving EC2 instances: %v", err)
	}

	// Iterate over each EC2 instance retrieved
	for instanceID := range ec2Instances {
		// Fetch the running software dynamically using SSM
		runningSoftware, err := GetRunningSoftware(cfg, instanceID)
		if err != nil {
			return fmt.Errorf("error retrieving running software for instance %s: %v", instanceID, err)
		}

		// Find the corresponding EC2 configuration from the config file (if any authorized software list exists for this instance)
		var ec2Config *config.EC2Config
		for _, configInstance := range awsConfig.EC2Instances {
			if configInstance.InstanceID == instanceID {
				ec2Config = &configInstance
				break
			}
		}

		// If no authorized software is configured for this instance, skip compliance check
		if ec2Config == nil {
			continue
		}

		// Check compliance by comparing running software to authorized software
		for _, software := range runningSoftware {
			if !contains(ec2Config.AuthorizedSoftware, software) {
				// Return the error as soon as an unauthorized software is detected
				return fmt.Errorf("unauthorized software detected on instance %s: %s", instanceID, software)
			}
		}
	}

	// If no non-compliant software is found, return nil
	return nil
}

// RunSoftwareExecutionCheck runs the periodic review of authorized software on AWS EC2 instances
func RunSoftwareExecutionCheck(cfg aws.Config) error {
	// Access authorized software configuration from the loaded config
	awsConfig := config.AppConfig.AWS

	fmt.Println("Starting AWS Software Execution Review")
	for _, ec2Instance := range awsConfig.EC2Instances {
		fmt.Printf("Authorized software for instance %s: %v\n",
			ec2Instance.InstanceID, ec2Instance.AuthorizedSoftware)
	}
	fmt.Println("---------------------------------------")

	// Check authorized software on EC2 instances
	err := CheckAuthorizedSoftware(cfg, &awsConfig)
	if err != nil {
		fmt.Println("Non-compliant software found:")
		fmt.Printf("%v\n", err)
		return err
	}

	fmt.Println("AWS Software Execution Review completed successfully")
	return nil
}
