package incident_response

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/crypto/ssh"
)

// Function to execute SSH command on EC2 instance
func executeSSHCommand(ipAddress string, command string) error {
	// Caricare la configurazione dell'attaccante dal file YAML
	attackerConfig := config.AppConfig.AWS.AttackerInstance
	// Ensure the SSH key file exists in the project
	keyPath := filepath.Join("internal", "checks", "incident_rensponse", "attackerkey.pem")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("SSH key not found at path: %s", keyPath)
	}

	// Use keyPath as the path to the private key file
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: attackerConfig.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", ipAddress+":22", config)
	if err != nil {
		return fmt.Errorf("failed to connect via SSH: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Errorf("failed to run command: %v, output: %s", err, output)
	}

	fmt.Printf("Command output: %s\n", output)
	return nil
}

func getVictimIPAddress(cfg aws.Config) (string, error) {
	_, victimIPAddress, err := findInstanceByTag(cfg, "victim")
	if err != nil {
		return "", fmt.Errorf("failed to find victim IP: %v", err)
	}
	return victimIPAddress, nil
}

func allowSSHAccess(cfg aws.Config, securityGroupID string) error {
	svc := ec2.NewFromConfig(cfg)

	authorizeIngressInput := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: &securityGroupID,
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges: []ec2types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
		},
	}

	_, err := svc.AuthorizeSecurityGroupIngress(context.TODO(), authorizeIngressInput)
	if err != nil {
		if strings.Contains(err.Error(), "InvalidPermission.Duplicate") {
			fmt.Println("SSH access rule already exists")
		} else {
			return fmt.Errorf("failed to allow SSH access: %v", err)
		}
	}

	fmt.Println("SSH access allowed for security group:", securityGroupID)
	return nil
}

func executeSSHCommandWithOutput(ipaddress string, command string) (string, error) {
	// Load attacker configuration from YAML file
	attackerConfig := config.AppConfig.AWS.AttackerInstance
	// Ensure the SSH key file exists in the project
	keyPath := filepath.Join("internal", "checks", "incident_rensponse", "attackerkey.pem")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", fmt.Errorf("SSH key not found at path: %s", keyPath)
	}

	// Use keyPath as the path to the private key file
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: attackerConfig.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", ipaddress+":22", config)
	if err != nil {
		return "", fmt.Errorf("failed to connect via SSH: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v, output: %s", err, output)
	}

	fmt.Printf("Command output: %s\n", output)
	return string(output), nil
}
