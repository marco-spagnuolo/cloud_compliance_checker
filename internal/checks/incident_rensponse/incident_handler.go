package incident_response

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// CheckIncidentHandling simula l'intero flusso di gestione degli incidenti con attacchi Nmap e Hydra
// Function to simulate the complete incident handling process with Nmap and Hydra attacks
func CheckIncidentHandling(cfg aws.Config) error {
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
		return fmt.Errorf("error during Nmap attack: %v", err)
	}
	fmt.Println("Nmap attack simulation completed successfully.")

	// Step 3: Simulate Hydra attack
	fmt.Println("Starting Hydra brute force attack simulation...")
	err = simulateHydraAttack(cfg)
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
	err = SendAlert(cfg, "arn:aws:sns:us-east-1:682033472444:IncidentAlert", alertMessage)
	if err != nil {
		return fmt.Errorf("error sending SNS alert: %v", err)
	}
	fmt.Println("Incident response workflow after Nmap and Hydra attacks completed successfully.")
	return nil
}

// Function to unblock and make the victim instance vulnerable before the attack
func unblockAndMakeVulnerable(cfg aws.Config, instanceID, ipAddress string) error {
	// Step 1: Unblock the victim instance by restoring security group rules
	fmt.Println("Unblocking victim instance...")
	err := unblockEC2Instance(cfg, instanceID)
	if err != nil {
		return fmt.Errorf("error unblocking EC2 instance: %v", err)
	}
	fmt.Println("Victim instance unblocked successfully.")

	// Step 2: Make the victim instance more vulnerable (enable password auth and remove limits)
	fmt.Println("Making the victim more vulnerable to brute force attacks...")
	err = makeVictimVulnerable(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to make victim vulnerable: %v", err)
	}
	fmt.Println("Victim instance made vulnerable.")
	return nil
}

// Enable password authentication and remove rate limiting
func makeVictimVulnerable(ipAddress string) error {
	enablePasswordAuthCommand := `
		sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config &&
		sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 1000/' /etc/ssh/sshd_config &&  
		sudo sed -i 's/#LoginGraceTime 2m/LoginGraceTime 10m/' /etc/ssh/sshd_config &&  
		sudo systemctl restart sshd
	`
	return executeSSHCommand(ipAddress, enablePasswordAuthCommand)
}
