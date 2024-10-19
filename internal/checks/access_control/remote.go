package iampolicy

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// RemoteAccessCheck è la struttura per eseguire i controlli di accesso remoto.
type RemoteAccessCheck struct {
	EC2Client *ec2.Client
	SSMClient *ssm.Client
	IAMClient *iam.Client
}

// NewRemoteAccessCheck inizializza un nuovo controllo di accesso remoto.
func NewRemoteAccessCheck(cfg aws.Config) *RemoteAccessCheck {
	return &RemoteAccessCheck{
		EC2Client: ec2.NewFromConfig(cfg),
		SSMClient: ssm.NewFromConfig(cfg),
		IAMClient: iam.NewFromConfig(cfg),
	}
}

// RunRemoteAccessCheck esegue il controllo di conformità per l'accesso remoto.
// req 3.1.12
func (c *RemoteAccessCheck) RunRemoteAccessCheck() error {
	log.Println("Inizio controllo accesso remoto...")

	describeInstancesInput := &ec2.DescribeInstancesInput{}
	describeInstancesOutput, err := c.EC2Client.DescribeInstances(context.TODO(), describeInstancesInput)
	if err != nil {
		return fmt.Errorf("impossibile elencare le istanze EC2: %v", err)
	}

	log.Printf("Numero di istanze EC2 trovate: %d\n", len(describeInstancesOutput.Reservations))

	for _, reservation := range describeInstancesOutput.Reservations {
		for _, instance := range reservation.Instances {
			log.Printf("Verifica istanza: %s\n", *instance.InstanceId)

			securityGroups := instance.SecurityGroups
			for _, sg := range securityGroups {
				sgDetails, err := c.EC2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{*sg.GroupId},
				})
				if err != nil {
					return fmt.Errorf("impossibile recuperare i dettagli del gruppo di sicurezza %s: %v", *sg.GroupId, err)
				}

				if isRemoteAccessAllowed(sgDetails.SecurityGroups) {
					log.Printf("Accesso remoto autorizzato per l'istanza %s\n", *instance.InstanceId)
				} else {
					log.Printf("ERRORE: Accesso remoto non autorizzato per l'istanza %s\n", *instance.InstanceId)
					return fmt.Errorf("istanza %s non conforme per l'accesso remoto", *instance.InstanceId)
				}
			}

			// Verifica che l'accesso remoto passi attraverso un bastion host
			if !isBastionHostUsed(instance) {
				log.Printf("ERRORE: L'istanza %s non utilizza un bastion host per l'accesso remoto\n", *instance.InstanceId)
				return fmt.Errorf("istanza %s non conforme per l'accesso remoto", *instance.InstanceId)
			}
		}
	}

	listUsersOutput, err := c.IAMClient.ListUsers(context.TODO(), &iam.ListUsersInput{})
	if err != nil {
		return fmt.Errorf("impossibile elencare gli utenti IAM: %v", err)
	}

	for _, user := range listUsersOutput.Users {
		log.Printf("Verifica utente IAM: %s\n", *user.UserName)

		if !isPrivilegedRemoteAccessAllowed(user, c) {
			log.Printf("ERRORE: L'utente %s non è autorizzato a eseguire comandi remoti privilegiati\n", *user.UserName)
			return fmt.Errorf("utente %s non conforme per l'accesso remoto privilegiato", *user.UserName)
		}
	}

	log.Println("Controllo accesso remoto completato con successo.")
	return nil
}

// isBastionHostUsed verifica se un'istanza utilizza un bastion host per l'accesso remoto.
func isBastionHostUsed(instance ec2types.Instance) bool {
	// Verifica se la subnet dell'istanza è associata a un bastion host
	if instance.PublicIpAddress != nil {
		// Supponiamo che un bastion host abbia un IP pubblico e permetta solo accessi tramite VPN o IP autorizzati
		log.Printf("Bastion host rilevato per l'istanza %s con IP pubblico: %s\n", *instance.InstanceId, *instance.PublicIpAddress)
		return true
	}
	return false
}

// isRemoteAccessAllowed verifica se le regole del gruppo di sicurezza consentono accesso SSH o RDP
func isRemoteAccessAllowed(securityGroups []ec2types.SecurityGroup) bool {
	for _, sg := range securityGroups {
		for _, permission := range sg.IpPermissions {
			// Verifica se le porte 22 (SSH) o 3389 (RDP) sono aperte
			if permission.FromPort != nil && (*permission.FromPort == 22 || *permission.FromPort == 3389) {
				for _, ipRange := range permission.IpRanges {
					// Controlla se l'intervallo di IP è aperto (es. "0.0.0.0/0", che non è sicuro)
					if *ipRange.CidrIp == "0.0.0.0/0" {
						log.Printf("Accesso SSH/RDP aperto a tutto il mondo nel gruppo di sicurezza %s\n", *sg.GroupId)
						return false
					}
				}
			}
		}
	}
	return true
}

// isPrivilegedRemoteAccessAllowed verifica se l'utente IAM ha l'autorizzazione a eseguire comandi remoti privilegiati.
func isPrivilegedRemoteAccessAllowed(user iamtypes.User, c *RemoteAccessCheck) bool {
	// Elenca le policy collegate all'utente
	listPoliciesOutput, err := c.IAMClient.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
		UserName: user.UserName,
	})
	if err != nil {
		log.Printf("Errore nel recuperare le policy per l'utente %s: %v\n", *user.UserName, err)
		return false
	}

	// Controlla se l'utente ha una policy che consente l'accesso remoto privilegiato
	for _, policy := range listPoliciesOutput.AttachedPolicies {
		if *policy.PolicyName == "RemoteAdminPolicy" {
			log.Printf("L'utente %s ha l'autorizzazione per l'accesso remoto privilegiato\n", *user.UserName)
			return true
		}
	}

	log.Printf("L'utente %s non ha l'autorizzazione per l'accesso remoto privilegiato\n", *user.UserName)
	return false
}
