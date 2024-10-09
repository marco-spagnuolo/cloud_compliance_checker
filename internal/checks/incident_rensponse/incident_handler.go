package incident_response

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// CheckIncidentHandling simula l'intero flusso di gestione degli incidenti con attacchi Nmap e Hydra
// Function to simulate the complete incident handling process with Nmap and Hydra attacks
func CheckIncidentHandlingNoUpload(cfg aws.Config) error {
	// Step 1: Get or launch victim instance and unblock it
	victimInstanceID, victimIPAddress, err := launchInstanceIfNotExists(cfg, "victim")
	if err != nil {
		return fmt.Errorf("failed to get or launch victim instance: %v", err)
	}

	fmt.Println("Unblocking victim instance and making it vulnerable before the attack...")
	err = unblockAndMakeVulnerable(cfg, victimInstanceID, victimIPAddress)
	if err != nil {
		return fmt.Errorf("error unblocking or making victim vulnerable: %v", err)
	}
	fmt.Println("Victim instance unblocked and made vulnerable.")

	// Step 2: Simulate Nmap attack
	fmt.Println("Starting Nmap attack simulation...")
	err = simulateNmapAttack(cfg)
	if err != nil {
		return fmt.Errorf("error during blindshell attack: %v", err)
	}
	fmt.Println("Nmap attack simulation completed successfully.")

	// Step 3: Simulate Hydra attack
	fmt.Println("Starting Hydra brute force attack simulation...")
	err = simulateHydraAttack(cfg, false)
	if err != nil {
		return fmt.Errorf("error during Hydra attack: %v", err)
	}
	fmt.Println("Hydra brute force attack simulation completed successfully.")

	// Step 4: Detect incidents using GuardDuty
	fmt.Println("Starting detection of incidents after Nmap and Hydra attacks...")
	err = detectIncidents(cfg)
	if err != nil {
		return fmt.Errorf("error detecting incidents: %v", err)
	}

	// Step 5: Isolate victim instance after the attack
	fmt.Println("Isolating the victim instance after the attack to prevent further vulnerability...")
	err = isolateEC2Instance(cfg, victimInstanceID)
	if err != nil {
		return fmt.Errorf("error isolating victim instance: %v", err)
	}
	fmt.Println("Victim instance isolated successfully.")

	// Step 6: Send an alert using SNS if needed
	alertMessage := "Incident detected after Nmap and Hydra attacks, and action taken. Victim instance isolated."
	fmt.Printf("Sending SNS alert with message: %s\n", alertMessage)
	err = SendAlert(cfg, alertMessage)
	if err != nil {
		return fmt.Errorf("error sending SNS alert: %v", err)
	}
	fmt.Println("Incident response workflow after Nmap and Hydra attacks completed successfully.")
	return nil
}

// Send an SNS alert with the incident response status
func SendAlert(cfg aws.Config, message string) error {
	topicArn := config.AppConfig.AWS.SnsTopicArn
	fmt.Printf("Sending SNS alert with message: %s\n", message)
	fmt.Printf("SNS topic ARN: %s\n", topicArn)
	if topicArn == "" {
		return fmt.Errorf("SNS topic ARN not found in configuration")
	}
	snsClient := sns.NewFromConfig(cfg)

	_, err := snsClient.Publish(context.TODO(), &sns.PublishInput{
		Message:  &message,
		TopicArn: &topicArn,
	})
	if err != nil {
		return fmt.Errorf("failed to send SNS alert: %v", err)
	}
	return nil
}

// CheckIncidentHandling simula l'intero flusso di gestione degli incidenti con attacchi Nmap e Hydra
func CheckIncidentHandlingUploads3(cfg aws.Config) error {
	// Step 1: Get or launch victim instance and unblock it
	victimInstanceID, victimIPAddress, err := launchInstanceIfNotExists(cfg, "victim")
	if err != nil {
		return fmt.Errorf("failed to get or launch victim instance: %v", err)
	}
	fmt.Println("Unblocking victim instance and making it vulnerable before the attack...")
	err = unblockAndMakeVulnerable(cfg, victimInstanceID, victimIPAddress)
	if err != nil {
		return fmt.Errorf("error unblocking or making victim vulnerable: %v", err)
	}
	fmt.Println("Victim instance unblocked and made vulnerable.")

	// Step 2: Simulate Nmap attack
	fmt.Println("Starting Nmap attack simulation...")
	err = simulateNmapAttack(cfg)
	if err != nil {
		return fmt.Errorf("error during blindshell attack: %v", err)
	}
	fmt.Println("Nmap attack simulation completed successfully.")

	// Step 3: Simulate Hydra attack
	fmt.Println("Starting Hydra brute force attack simulation...")
	err = simulateHydraAttack(cfg, false)
	if err != nil {
		return fmt.Errorf("error during Hydra attack: %v", err)
	}
	fmt.Println("Hydra brute force attack simulation completed successfully.")

	// Step 4: Detect incidents using GuardDuty and save results in a JSON file
	fmt.Println("Collecting incidents from GuardDuty and saving them in a JSON file...")
	err = collectAndSaveGuardDutyFindings(cfg)
	if err != nil {
		return fmt.Errorf("error collecting GuardDuty findings: %v", err)
	}

	// Step 5: Isolate victim instance after the attack
	fmt.Println("Isolating the victim instance after the attack to prevent further vulnerability...")
	err = isolateEC2Instance(cfg, victimInstanceID)
	if err != nil {
		return fmt.Errorf("error isolating victim instance: %v", err)
	}
	fmt.Println("Victim instance isolated successfully.")

	// Step 6: Send an alert using SNS if needed
	alertMessage := "Incident detected after Nmap and Hydra attacks, and action taken. Victim instance isolated."
	fmt.Printf("Sending SNS alert with message: %s\n", alertMessage)
	err = SendAlert(cfg, alertMessage)
	if err != nil {
		return fmt.Errorf("error sending SNS alert: %v", err)
	}
	fmt.Println("Incident response workflow after Nmap and Hydra attacks completed successfully.")
	return nil
}

// parseTime analizza il tempo in una stringa
func parseTime(timeStr string) string {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return timeStr
	}
	return t.Format("2006-01-02 15:04:05")
}

// Funzione per stampare l'identità dell'utente AWS
func printCallerIdentity(cfg aws.Config) error {
	stsClient := sts.NewFromConfig(cfg)

	identityOutput, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %v", err)
	}

	fmt.Printf("AWS Caller Identity:\n")
	fmt.Printf("Account: %s\n", *identityOutput.Account)
	fmt.Printf("ARN: %s\n", *identityOutput.Arn)
	fmt.Printf("User ID: %s\n", *identityOutput.UserId)

	return nil
}

// CheckIncidentHandling gestisce il flusso di gestione degli incidenti con un flag per scegliere l'upload
func CheckIncidentHandling(cfg aws.Config, uploadToS3 bool) error {
	if !uploadToS3 {
		return CheckIncidentHandlingNoUpload(cfg)
	} else {
		return CheckIncidentHandlingUploads3(cfg)
	}
}
