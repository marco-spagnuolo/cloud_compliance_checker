package incident_response

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

// SimulateRealIncident crea e simula un incidente reale sulle tue istanze EC2
func SimulateRealIncident(cfg aws.Config) error {
	// Step 1: Lanciare tentativi di accesso SSH falliti su una delle istanze
	fmt.Println("Simulating failed SSH login attempts...")
	err := simulateHydraAttack(cfg, false)
	if err != nil {
		return fmt.Errorf("failed to simulate SSH attempts: %v", err)
	}

	// Step 2: Modificare il Security Group dell'istanza
	fmt.Println("Modifying Security Group to open unauthorized ports...")
	err = modifySecurityGroup(cfg)
	if err != nil {
		return fmt.Errorf("failed to modify security group: %v", err)
	}

	// Step 3: Tentativo di connessione su una porta aperta non autorizzata
	fmt.Println("Simulating unauthorized connection attempt...")
	err = simulateUnauthorizedConnection(cfg)
	if err != nil {
		return fmt.Errorf("failed to simulate unauthorized connection: %v", err)
	}

	// Step 4: Attendere il rilevamento di GuardDuty e raccogliere gli incidenti
	fmt.Println("Waiting for GuardDuty to detect suspicious activity...")

	err = detectRecentGuardDutyFindings(cfg)
	if err != nil {
		return fmt.Errorf("failed to detect incidents with GuardDuty: %v", err)
	}

	fmt.Println("Incident simulation completed successfully.")
	return nil
}

// simulateFailedSSHAttempts simula tentativi di accesso SSH falliti su una delle istanze
func simulateFailedSSHAttempts(cfg aws.Config) error {
	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Esegui comandi SSH con credenziali sbagliate
	for i := 0; i < 5; i++ {
		cmd := exec.Command("ssh", "fakeuser@"+victimIPAddress)
		err := cmd.Run()
		if err != nil {
			fmt.Printf("SSH attempt %d failed as expected.\n", i+1)
		} else {
			return fmt.Errorf("SSH attempt unexpectedly succeeded")
		}
	}

	return nil
}

// modifySecurityGroup modifica il Security Group per aprire una porta non autorizzata
func modifySecurityGroup(cfg aws.Config) error {
	ec2Client := ec2.NewFromConfig(cfg)

	// Ottieni l'ID del security group dalla configurazione
	securityGroupID := config.AppConfig.AWS.AttackerInstance.SecurityGroup

	if securityGroupID == "" {
		return fmt.Errorf("security group ID is missing from configuration")
	}

	// Verifica se la regola esiste già
	fmt.Printf("Checking if port 8080 is already open on security group %s...\n", securityGroupID)
	describeInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{securityGroupID},
	}

	describeOutput, err := ec2Client.DescribeSecurityGroups(context.TODO(), describeInput)
	if err != nil {
		return fmt.Errorf("failed to describe security group: %v", err)
	}

	// Controlla se la regola per la porta 8080 esiste già
	for _, sg := range describeOutput.SecurityGroups {
		for _, permission := range sg.IpPermissions {
			if aws.ToString(permission.IpProtocol) == "tcp" &&
				aws.ToInt32(permission.FromPort) == 8080 &&
				aws.ToInt32(permission.ToPort) == 8080 {
				fmt.Println("Port 8080 is already open. No need to modify the security group.")
				return nil
			}
		}
	}

	// Aggiungi una regola per aprire la porta 8080 se non esiste
	fmt.Printf("Modifying security group %s to open port 8080...\n", securityGroupID)
	_, err = ec2Client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: &securityGroupID,
		IpPermissions: []types.IpPermission{
			{
				FromPort:   aws.Int32(8080),
				ToPort:     aws.Int32(8080),
				IpProtocol: aws.String("tcp"),
				IpRanges: []types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		},
	})
	if err != nil {
		fmt.Printf("Failed to modify security group: %v\n", err)
		return fmt.Errorf("failed to authorize ingress rule: %v", err)
	}

	fmt.Println("Security group modified successfully to open port 8080.")
	return nil
}

// simulateUnauthorizedConnection tenta una connessione non autorizzata a una porta aperta
func simulateUnauthorizedConnection(cfg aws.Config) error {
	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Prova a connetterti alla porta aperta (8080)
	cmd := exec.Command("nc", "-v", victimIPAddress, "8080")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Unauthorized connection attempt failed as expected.")
	} else {
		return fmt.Errorf("Unauthorized connection attempt unexpectedly succeeded")
	}

	return nil
}

// simulatePortScan simula una scansione delle porte della vittima
func simulatePortScan(cfg aws.Config) error {
	victimIPAddress, err := getVictimIPAddress(cfg)
	if err != nil {
		return fmt.Errorf("failed to get victim IP: %v", err)
	}

	// Simula una scansione delle porte usando nmap
	cmd := exec.Command("nmap", "-sS", "-p-", victimIPAddress)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("port scan failed: %v", err)
	}

	fmt.Printf("Port scan result: %s\n", string(output))
	return nil
}

// detectRecentGuardDutyFindings rileva gli incidenti simulati con GuardDuty e verifica che siano recenti
func detectRecentGuardDutyFindings(cfg aws.Config) error {
	client := guardduty.NewFromConfig(cfg)

	// Recupera l'elenco dei detector GuardDuty
	listDetectorsInput := &guardduty.ListDetectorsInput{}
	detectors, err := client.ListDetectors(context.TODO(), listDetectorsInput)
	if err != nil {
		return fmt.Errorf("failed to list GuardDuty detectors: %v", err)
	}

	if len(detectors.DetectorIds) == 0 {
		return fmt.Errorf("no GuardDuty detectors found")
	}

	// Prendi il primo detector per esempio
	detectorID := detectors.DetectorIds[0]
	fmt.Printf("Found GuardDuty detector: %s\n", detectorID)

	// Recupera i findings (incidenti simulati)
	findingsInput := &guardduty.ListFindingsInput{
		DetectorId: &detectorID,
	}
	findings, err := client.ListFindings(context.TODO(), findingsInput)
	if err != nil {
		return fmt.Errorf("failed to list GuardDuty findings: %v", err)
	}

	if len(findings.FindingIds) == 0 {
		fmt.Println("No findings detected by GuardDuty.")
		return nil
	}

	// Recupera i dettagli degli incidenti e controlla se sono recenti (nell'ultima ora)
	getFindingInput := &guardduty.GetFindingsInput{
		DetectorId: &detectorID,
		FindingIds: findings.FindingIds,
	}
	findingOutput, err := client.GetFindings(context.TODO(), getFindingInput)
	if err != nil {
		return fmt.Errorf("failed to get details for findings: %v", err)
	}

	recentFindings := 0
	oneHourAgo := time.Now().Add(-1 * time.Hour)

	for _, finding := range findingOutput.Findings {
		findingTime, err := time.Parse(time.RFC3339, *finding.Service.EventFirstSeen)
		if err != nil {
			fmt.Printf("Error parsing finding time: %v\n", err)
			continue
		}

		if findingTime.After(oneHourAgo) {
			fmt.Printf("Recent finding detected: ID=%s, Type=%s, Time=%s\n",
				*finding.Id, *finding.Type, findingTime.Format("2024-01-02 15:04:05"))
			recentFindings++
		}
	}

	if recentFindings == 0 {
		fmt.Println("No recent findings detected by GuardDuty within the last hour.")
	} else {
		fmt.Printf("%d recent findings detected by GuardDuty.\n", recentFindings)
	}

	return nil
}
