package policy

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/viper"
)

// IAMCheck è una struttura che implementa il controllo della conformità alle policy IAM e altri controlli AWS
type IAMCheck struct {
	EC2Client *ec2.Client
	S3Client  *s3.Client
	IAMClient *iam.Client
}

// NewIAMCheck inizializza una nuova istanza di IAMCheck
func NewIAMCheck(cfg aws.Config) *IAMCheck {
	return &IAMCheck{
		EC2Client: ec2.NewFromConfig(cfg),
		S3Client:  s3.NewFromConfig(cfg),
		IAMClient: iam.NewFromConfig(cfg),
	}
}

// User rappresenta un utente con le sue policy dal file di configurazione YAML
type User struct {
	Name     string
	Policies []string
}

// loadUsersFromConfig carica gli utenti e le relative policy dal file YAML
func loadUsersFromConfig() (map[string]User, error) {
	viper.SetConfigFile("cred.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("errore nella lettura del file di configurazione: %v", err)
	}

	// Leggi gli utenti dal file YAML
	var usersConfig []User
	err = viper.UnmarshalKey("aws.users", &usersConfig)
	if err != nil {
		return nil, fmt.Errorf("errore nella decodifica degli utenti dal file di configurazione: %v", err)
	}

	usersMap := make(map[string]User)
	for _, user := range usersConfig {
		usersMap[user.Name] = user
	}

	return usersMap, nil
}

// isPolicyInUserConfig verifica se una policy è assegnata a un utente nel file di configurazione
func isPolicyInUserConfig(userPolicies []string, policyName string) bool {
	for _, policy := range userPolicies {
		if policy == policyName {
			return true
		}
	}
	return false
}

// RunSecurityGroupCheck esegue il controllo di conformità sui gruppi di sicurezza
func (c *IAMCheck) RunSecurityGroupCheck() error {
	// Elenca i gruppi di sicurezza
	describeSGOutput, err := c.EC2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return fmt.Errorf("impossibile elencare i gruppi di sicurezza: %v", err)
	}

	// Carica i gruppi di sicurezza dal file di configurazione
	var securityGroups []config.SecurityGroup
	err = viper.UnmarshalKey("aws.security_groups", &securityGroups)
	if err != nil {
		return fmt.Errorf("errore nella decodifica dei gruppi di sicurezza dal file di configurazione: %v", err)
	}

	// Mappa i gruppi di sicurezza configurati
	sgMap := make(map[string]config.SecurityGroup)
	for _, sg := range securityGroups {
		sgMap[sg.Name] = sg
	}

	// Variabile per tenere traccia della conformità generale
	isCompliant := true

	// Verifica i gruppi di sicurezza elencati su AWS
	for _, awsSG := range describeSGOutput.SecurityGroups {
		fmt.Printf("Verifica del gruppo di sicurezza: %s\n", *awsSG.GroupName)

		configSG, ok := sgMap[*awsSG.GroupName]
		if !ok {
			// Se il gruppo di sicurezza non è trovato nella configurazione, segna come non conforme
			fmt.Printf("Gruppo di sicurezza %s non trovato nella configurazione\n", *awsSG.GroupName)
			isCompliant = false
			continue
		}

		// Verifica le porte di ingresso
		if awsSG.IpPermissions != nil {
			for _, ingress := range awsSG.IpPermissions {
				if ingress.FromPort != nil {
					if !contains(configSG.AllowedIngressPorts, int(*ingress.FromPort)) {
						fmt.Printf("Porta di ingresso %d non consentita per il gruppo %s\n", *ingress.FromPort, *awsSG.GroupName)
						isCompliant = false
					}
				}
			}
		}

		// Verifica le porte di uscita
		if awsSG.IpPermissionsEgress != nil {
			for _, egress := range awsSG.IpPermissionsEgress {
				if egress.FromPort != nil {
					if !contains(configSG.AllowedEgressPorts, int(*egress.FromPort)) {
						fmt.Printf("Porta di uscita %d non consentita per il gruppo %s\n", *egress.FromPort, *awsSG.GroupName)
						isCompliant = false
					}
				}
			}
		}
	}

	if !isCompliant {
		return fmt.Errorf("uno o più gruppi di sicurezza non sono conformi")
	}

	return nil
}

// RunS3BucketCheck esegue il controllo di conformità sui bucket S3
func (c *IAMCheck) RunS3BucketCheck() error {
	// Elenca i bucket S3
	listBucketsOutput, err := c.S3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("impossibile elencare i bucket S3: %v", err)
	}

	// Carica i bucket dal file di configurazione
	var s3Buckets []config.S3Bucket
	err = viper.UnmarshalKey("aws.s3_buckets", &s3Buckets)
	if err != nil {
		return fmt.Errorf("errore nella decodifica dei bucket S3 dal file di configurazione: %v", err)
	}

	// Mappa i bucket configurati
	bucketMap := make(map[string]config.S3Bucket)
	for _, bucket := range s3Buckets {
		bucketMap[bucket.Name] = bucket
	}

	// Variabile per tenere traccia della conformità generale
	isCompliant := true

	// Verifica i bucket elencati su AWS
	for _, awsBucket := range listBucketsOutput.Buckets {
		fmt.Printf("Verifica del bucket S3: %s\n", *awsBucket.Name)

		configBucket, ok := bucketMap[*awsBucket.Name]
		if !ok {
			// Se il bucket non è trovato nella configurazione, segna come non conforme
			fmt.Printf("Bucket %s non trovato nella configurazione\n", *awsBucket.Name)
			isCompliant = false
			continue
		}

		// Verifica la crittografia del bucket
		getBucketEncryptionOutput, err := c.S3Client.GetBucketEncryption(context.TODO(), &s3.GetBucketEncryptionInput{
			Bucket: awsBucket.Name,
		})
		if err != nil {
			fmt.Printf("Impossibile ottenere la crittografia del bucket %s: %v\n", *awsBucket.Name, err)
			isCompliant = false
			continue
		}

		// Confronta il tipo di crittografia con quello configurato
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

// Funzione di supporto per verificare se un valore è contenuto in una lista
func contains(list []int, elem int) bool {
	for _, v := range list {
		if v == elem {
			return true
		}
	}
	return false
}

// Run esegue il controllo per il requisito NIST 3.1.1
func (c *IAMCheck) Run() error {
	// Elenca gli utenti IAM su AWS
	listUsersOutput, err := c.IAMClient.ListUsers(context.TODO(), &iam.ListUsersInput{})
	if err != nil {
		return fmt.Errorf("impossibile elencare gli utenti IAM: %v", err)
	}

	// Carica la configurazione utenti e policy dal file YAML
	usersFromConfig, err := loadUsersFromConfig()
	if err != nil {
		return fmt.Errorf("impossibile caricare gli utenti dal file di configurazione: %v", err)
	}

	// Itera sugli utenti AWS e verifica le policy assegnate
	for _, awsUser := range listUsersOutput.Users {
		fmt.Printf("=======> Verifica dell'utente AWS: %s\n", *awsUser.UserName)

		// Elenca le policy assegnate all'utente su AWS
		attachedPoliciesOutput, err := c.IAMClient.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
			UserName: awsUser.UserName,
		})
		if err != nil {
			return fmt.Errorf("impossibile elencare le policy assegnate all'utente %s: %v", *awsUser.UserName, err)
		}

		// Cerca l'utente nel file di configurazione
		configUser, ok := usersFromConfig[*awsUser.UserName]
		if !ok {
			return fmt.Errorf("l'utente %s non è presente nel file di configurazione", *awsUser.UserName)
		}

		// Verifica la conformità delle policy
		for _, awsPolicy := range attachedPoliciesOutput.AttachedPolicies {
			fmt.Printf("=======> L'utente %s ha la policy: %s\n", *awsUser.UserName, *awsPolicy.PolicyName)

			// Confronta la policy assegnata su AWS con quelle definite nel file YAML
			if !isPolicyInUserConfig(configUser.Policies, *awsPolicy.PolicyName) {
				return fmt.Errorf("policy %s non conforme per l'utente %s: non è presente nel file di configurazione", *awsPolicy.PolicyName, *awsUser.UserName)
			}
		}
	}

	return nil
}

// RunCheckAcceptedPolicies esegue il controllo per il requisito NIST 3.1.2
func (c *IAMCheck) RunCheckAcceptedPolicies() error {
	// Ottieni le policy accettate dalla configurazione
	acceptedPolicies := config.AppConfig.AWS.AcceptedPolicies

	// Elenca tutte le policy gestite su AWS
	listPoliciesOutput, err := c.IAMClient.ListPolicies(context.TODO(), &iam.ListPoliciesInput{})
	if err != nil {
		return fmt.Errorf("impossibile elencare le policy su AWS: %v", err)
	}

	// Crea una mappa per verificare più facilmente se una policy è presente su AWS
	policiesOnAWS := make(map[string]bool)
	for _, policy := range listPoliciesOutput.Policies {
		policiesOnAWS[*policy.PolicyName] = true
	}

	// Verifica se le policy accettate nel file di configurazione esistono su AWS
	for _, acceptedPolicy := range acceptedPolicies {
		if _, exists := policiesOnAWS[acceptedPolicy]; !exists {
			return fmt.Errorf("policy accettata %s non trovata su AWS", acceptedPolicy)
		}
	}

	return nil
}

// RunCheckCUIFlow esegue i controlli di conformità richiesti per NIST SP 800-171 3.1.3
// Chiamando sia il controllo dei gruppi di sicurezza sia il controllo dei bucket S3
func (c *IAMCheck) RunCheckCUIFlow() error {
	// Esegue il controllo sui gruppi di sicurezza
	fmt.Println("===== Inizio controllo dei gruppi di sicurezza (3.1.3) =====")
	err := c.RunSecurityGroupCheck()
	if err != nil {
		return fmt.Errorf("errore durante il controllo dei gruppi di sicurezza: %v", err)
	}
	fmt.Println("===== Controllo dei gruppi di sicurezza completato =====")

	// Esegue il controllo sui bucket S3
	fmt.Println("===== Inizio controllo dei bucket S3 (3.1.3) =====")
	err = c.RunS3BucketCheck()
	if err != nil {
		return fmt.Errorf("errore durante il controllo dei bucket S3: %v", err)
	}
	fmt.Println("===== Controllo dei bucket S3 completato =====")

	return nil
}
