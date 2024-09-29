package utils

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// LogAndReturnError registra un errore e lo restituisce
func LogAndReturnError(message string, err error) error {
	log.Printf("ERRORE: %s: %v\n", message, err)
	return fmt.Errorf("%s: %v", message, err)
}

// ContainsString verifica se una stringa è contenuta in una lista di stringhe
func ContainsString(list []string, elem string) bool {
	for _, v := range list {
		if v == elem {
			return true
		}
	}
	return false
}

// contains verifica se un intero è presente in una lista di interi
func Contains(list []int, elem int) bool {
	for _, v := range list {
		if v == elem {
			return true
		}
	}
	return false
}

// mapPolicyToFunction mappa una policy AWS a una funzione sensibile
func mapPolicyToFunction(policyName string) string {
	switch policyName {
	case "IAMFullAccess":
		return "ManageIAM"
	case "AmazonEC2FullAccess":
		return "ManageEC2"
	default:
		return ""
	}
}

func MapAWSManagedPolicies(policies []iamtypes.Policy) map[string]bool {
	policiesMap := make(map[string]bool)
	for _, policy := range policies {
		policiesMap[*policy.PolicyName] = true
	}
	return policiesMap
}

// MapUsers trasforma una lista di utenti in una mappa per accesso rapido
func MapUsers(usersConfig []config.User) map[string]config.User {
	usersMap := make(map[string]config.User)
	for _, user := range usersConfig {
		usersMap[user.Name] = user
	}
	return usersMap
}

// MapRolesToFunctions mappa i ruoli IAM alle funzioni sensibili
func MapRolesToFunctions(roles []iamtypes.Role, iamClient *iam.Client) map[string][]string {
	roleFunctionMap := make(map[string][]string)
	for _, role := range roles {
		listAttachedRolePoliciesOutput, err := iamClient.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		})
		if err != nil {
			log.Printf("ERRORE: impossibile elencare le policy per il ruolo %s: %v\n", *role.RoleName, err)
			continue
		}

		var policies []string
		for _, policy := range listAttachedRolePoliciesOutput.AttachedPolicies {
			function := mapPolicyToFunction(*policy.PolicyName)
			if function != "" {
				policies = append(policies, function)
			}
		}
		roleFunctionMap[*role.RoleName] = policies
	}
	return roleFunctionMap
}

// VerifyCriticalRoleCompliance verifica la conformità dei ruoli critici
func VerifyCriticalRoleCompliance(criticalRole config.CriticalRole, roleFunctionMap map[string][]string) error {
	log.Printf("INFO: Verifica del ruolo critico: %s\n", criticalRole.RoleName)

	policies, ok := roleFunctionMap[criticalRole.RoleName]
	if !ok {
		log.Printf("ERRORE: Ruolo critico %s non trovato su AWS\n", criticalRole.RoleName)
		return fmt.Errorf("ruolo critico %s non trovato su AWS", criticalRole.RoleName)
	}

	log.Printf("INFO: Policy assegnate al ruolo critico %s: %+v\n", criticalRole.RoleName, policies)
	log.Printf("INFO: Funzioni sensibili attese per il ruolo %s: %+v\n", criticalRole.RoleName, criticalRole.SensitiveFunctions)

	for _, sensitiveFunction := range criticalRole.SensitiveFunctions {
		log.Printf("INFO: Controllo della funzione sensibile %s per il ruolo critico %s\n", sensitiveFunction, criticalRole.RoleName)
		if !ContainsString(policies, sensitiveFunction) {
			log.Printf("ERRORE: Funzione sensibile %s non assegnata al ruolo critico %s\n", sensitiveFunction, criticalRole.RoleName)
			return fmt.Errorf("funzione sensibile %s non assegnata al ruolo critico %s", sensitiveFunction, criticalRole.RoleName)
		}
		log.Printf("INFO: Funzione sensibile %s conforme per il ruolo critico %s\n", sensitiveFunction, criticalRole.RoleName)
	}

	return nil
}

// CheckSecurityGroupsCompliance verifica la conformità dei gruppi di sicurezza
func CheckSecurityGroupsCompliance(securityGroupsFromConfig []config.SecurityGroup, securityGroupsFromAWS []ec2.SecurityGroup) error {
	isCompliant := true

	sgMap := make(map[string]config.SecurityGroup)
	for _, sg := range securityGroupsFromConfig {
		sgMap[sg.Name] = sg
	}

	for _, awsSG := range securityGroupsFromAWS {
		fmt.Printf("Verifica del gruppo di sicurezza: %s\n", *awsSG.GroupName)

		configSG, ok := sgMap[*awsSG.GroupName]
		if !ok {
			fmt.Printf("Gruppo di sicurezza %s non trovato nella configurazione\n", *awsSG.GroupName)
			isCompliant = false
			continue
		}

		if awsSG.IpPermissions != nil {
			for _, ingress := range awsSG.IpPermissions {
				if ingress.FromPort != nil && !Contains(configSG.AllowedIngressPorts, int(*ingress.FromPort)) {
					fmt.Printf("Porta di ingresso %d non consentita per il gruppo %s\n", *ingress.FromPort, *awsSG.GroupName)
					isCompliant = false
				}
			}
		}

		if awsSG.IpPermissionsEgress != nil {
			for _, egress := range awsSG.IpPermissionsEgress {
				if egress.FromPort != nil && !Contains(configSG.AllowedEgressPorts, int(*egress.FromPort)) {
					fmt.Printf("Porta di uscita %d non consentita per il gruppo %s\n", *egress.FromPort, *awsSG.GroupName)
					isCompliant = false
				}
			}
		}
	}

	if !isCompliant {
		return fmt.Errorf("uno o più gruppi di sicurezza non sono conformi")
	}
	return nil
}

// CheckS3BucketsCompliance verifica la conformità dei bucket S3
func CheckS3BucketsCompliance(s3Client *s3.Client, s3BucketsFromConfig []config.S3Bucket, s3BucketsFromAWS []s3types.Bucket) error {
	isCompliant := true

	bucketMap := make(map[string]config.S3Bucket)
	for _, bucket := range s3BucketsFromConfig {
		bucketMap[bucket.Name] = bucket
	}

	for _, awsBucket := range s3BucketsFromAWS {
		fmt.Printf("Verifica del bucket S3: %s\n", *awsBucket.Name)

		configBucket, ok := bucketMap[*awsBucket.Name]
		if !ok {
			fmt.Printf("Bucket %s non trovato nella configurazione\n", *awsBucket.Name)
			isCompliant = false
			continue
		}

		getBucketEncryptionOutput, err := s3Client.GetBucketEncryption(context.TODO(), &s3.GetBucketEncryptionInput{
			Bucket: awsBucket.Name,
		})
		if err != nil {
			fmt.Printf("Impossibile ottenere la crittografia del bucket %s: %v\n", *awsBucket.Name, err)
			isCompliant = false
			continue
		}

		if getBucketEncryptionOutput.ServerSideEncryptionConfiguration != nil {
			encryption := getBucketEncryptionOutput.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
			if string(encryption) != configBucket.Encryption {
				fmt.Printf("Crittografia %s non conforme per il bucket %s (attesa: %s)\n", encryption, *awsBucket.Name, configBucket.Encryption)
				isCompliant = false
			} else {
				fmt.Printf("Crittografia conforme per il bucket %s\n", *awsBucket.Name)
			}
		}
	}

	if !isCompliant {
		return fmt.Errorf("uno o più bucket S3 non sono conformi")
	}
	return nil
}
