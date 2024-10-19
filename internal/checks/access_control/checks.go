package iampolicy

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/spf13/viper"
)

// IAMCheck is a struct that contains the AWS clients required for the IAM checks
type IAMCheck struct {
	EC2Client        *ec2.Client
	S3Client         *s3.Client
	IAMClient        *iam.Client
	CloudTrailClient *cloudtrail.Client
}

// NewIAMCheck initializes a new IAMCheck struct with the provided AWS configuration
func NewIAMCheck(cfg aws.Config) *IAMCheck {
	return &IAMCheck{
		EC2Client: ec2.NewFromConfig(cfg),
		S3Client:  s3.NewFromConfig(cfg),
		IAMClient: iam.NewFromConfig(cfg),
	}
}

func (c *IAMCheck) RunCheckPolicies() error {

	listUsersOutput, err := c.IAMClient.ListUsers(context.TODO(), &iam.ListUsersInput{})
	if err != nil {
		return LogAndReturnError("impossibile elencare gli utenti IAM", err)
	}

	// load users from config
	usersFromConfig := config.AppConfig.AWS.Users

	var nonConformingUsers []string

	for _, awsUser := range listUsersOutput.Users {
		log.Printf("=======> Verifica dell'utente AWS: %s\n", *awsUser.UserName)

		attachedPoliciesOutput, err := c.IAMClient.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
			UserName: awsUser.UserName,
		})
		if err != nil {
			return LogAndReturnError(fmt.Sprintf("impossibile elencare le policy assegnate all'utente %s", *awsUser.UserName), err)
		}

		var configUser *config.User
		for i, user := range usersFromConfig {
			if user.Name == *awsUser.UserName {
				configUser = &usersFromConfig[i]
				break
			}
		}

		if configUser == nil {
			log.Printf("ERRORE: L'utente %s non è presente nel file di configurazione\n", *awsUser.UserName)
			nonConformingUsers = append(nonConformingUsers, *awsUser.UserName) // Aggiungi l'utente non conforme
			continue                                                           // Se l'utente non è presente nel file di configurazione, continua con il prossimo utente
		}

		// Verifica se l'utente ha policy configurate
		if len(configUser.Policies) == 0 {
			log.Printf("ERRORE: Nessuna policy configurata per l'utente %s nel file YAML\n", configUser.Name)
			nonConformingUsers = append(nonConformingUsers, configUser.Name) // Aggiungi l'utente non conforme
			continue
		}

		// Verifica la conformità delle policy assegnate su AWS
		for _, awsPolicy := range attachedPoliciesOutput.AttachedPolicies {
			log.Printf("=======> L'utente %s ha la policy: %s\n", *awsUser.UserName, *awsPolicy.PolicyName)

			// Confronta la policy assegnata su AWS con quelle definite nel file YAML
			if !ContainsString(configUser.Policies, *awsPolicy.PolicyName) {
				log.Printf("ERRORE: La policy %s per l'utente %s non è conforme (non trovata nel file di configurazione)\n", *awsPolicy.PolicyName, *awsUser.UserName)
				nonConformingUsers = append(nonConformingUsers, configUser.Name) // Aggiungi l'utente non conforme
				continue
			}
		}

		// Verifica se ci sono policy nel file di configurazione che non sono presenti su AWS
		for _, configPolicy := range configUser.Policies {
			found := false
			for _, awsPolicy := range attachedPoliciesOutput.AttachedPolicies {
				if configPolicy == *awsPolicy.PolicyName {
					found = true
					break
				}
			}
			if !found {
				log.Printf("ERRORE: La policy %s definita per l'utente %s nel file YAML non è assegnata su AWS\n", configPolicy, configUser.Name)
				nonConformingUsers = append(nonConformingUsers, configUser.Name)
			}
		}
	}

	// Se ci sono utenti non conformi, restituisci un errore
	if len(nonConformingUsers) > 0 {
		return fmt.Errorf("trovati utenti non conformi: %v", nonConformingUsers)
	}

	return nil
}

// RunCheckAcceptedPolicies esegue il controllo per il requisito NIST 3.1.2
func (c *IAMCheck) RunCheckAcceptedPolicies() error {

	// Carica le policy accettate dal file di configurazione
	acceptedPolicies, err := loadAcceptedPoliciesFromConfig()
	if err != nil {
		return fmt.Errorf("impossibile caricare le policy accettate dal file di configurazione: %v", err)
	}

	// Lista le policy gestite su AWS
	listPoliciesOutput, err := c.IAMClient.ListPolicies(context.TODO(), &iam.ListPoliciesInput{})
	if err != nil {
		return fmt.Errorf("impossibile elencare le policy su AWS: %v", err)
	}

	// Log per verificare le policy effettivamente presenti su AWS
	log.Printf("INFO: Policy trovate su AWS:")
	for _, policy := range listPoliciesOutput.Policies {
		log.Printf("Policy trovata: %s/d", *policy.PolicyName)
	}

	policiesOnAWS := MapAWSManagedPolicies(listPoliciesOutput.Policies)

	// Confronta le policy accettate con quelle effettivamente presenti su AWS
	for _, acceptedPolicy := range acceptedPolicies {
		if _, exists := policiesOnAWS[acceptedPolicy]; !exists {
			log.Printf("ERRORE: Policy accettata %s non trovata su AWS", acceptedPolicy)
			return fmt.Errorf("policy accettata %s non trovata su AWS", acceptedPolicy)
		}
	}

	log.Println("INFO: Tutte le policy accettate sono conformi su AWS")
	return nil
}

// RunSecurityGroupCheck esegue il controllo di conformità sui gruppi di sicurezza
func RunSecurityGroupCheck(securityGroupsFromConfig []config.SecurityGroup, securityGroupsFromAWS []ec2types.SecurityGroup) error {
	isCompliant := true

	// Crea una mappa dei gruppi di sicurezza dalla configurazione per una ricerca rapida
	sgMap := make(map[string]config.SecurityGroup)
	for _, sg := range securityGroupsFromConfig {
		sgMap[sg.Name] = sg
	}

	// Itera su ogni gruppo di sicurezza AWS e confronta con la configurazione
	for _, awsSG := range securityGroupsFromAWS {
		log.Printf("Verifica del gruppo di sicurezza: %s\n", *awsSG.GroupName)

		// Cerca il gruppo di sicurezza nella configurazione
		configSG, ok := sgMap[*awsSG.GroupName]
		if !ok {
			// Se non trovato, segna il gruppo di sicurezza come non conforme
			log.Printf("Gruppo di sicurezza %s non trovato nella configurazione\n", *awsSG.GroupName)
			isCompliant = false
			continue
		}

		// Verifica le porte di ingresso
		if awsSG.IpPermissions != nil {
			for _, ingress := range awsSG.IpPermissions {
				if ingress.FromPort != nil && !Contains(configSG.AllowedIngressPorts, int(*ingress.FromPort)) {
					log.Printf("Porta di ingresso %d non consentita per il gruppo %s\n", *ingress.FromPort, *awsSG.GroupName)
					isCompliant = false
				}
			}
		}

		// Verifica le porte di uscita
		if awsSG.IpPermissionsEgress != nil {
			for _, egress := range awsSG.IpPermissionsEgress {
				if egress.FromPort != nil && !Contains(configSG.AllowedEgressPorts, int(*egress.FromPort)) {
					log.Printf("Porta di uscita %d non consentita per il gruppo %s\n", *egress.FromPort, *awsSG.GroupName)
					isCompliant = false
				}
			}
		}
	}

	// Se ci sono non conformità, restituisci un errore
	if !isCompliant {
		return fmt.Errorf("uno o più gruppi di sicurezza non sono conformi")
	}

	// Restituisci nil se tutti i controlli sono conformi
	return nil
}

// RunS3BucketCheck esegue il controllo di conformità sui bucket S3
func (c *IAMCheck) RunS3BucketCheck() error {
	listBucketsOutput, err := c.S3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		return LogAndReturnError("impossibile elencare i bucket S3", err)
	}

	s3BucketsFromConfig, err := loadS3BucketsFromConfig()
	if err != nil {
		return LogAndReturnError("errore nella decodifica dei bucket S3 dal file di configurazione", err)
	}

	return CheckS3BucketsCompliance(c.S3Client, s3BucketsFromConfig, listBucketsOutput.Buckets)
}

// RunCheckCUIFlow esegue i controlli di conformità richiesti per NIST SP 800-171 3.1.3
func (c *IAMCheck) RunCheckCUIFlow() error {
	log.Println("===== Inizio controllo dei gruppi di sicurezza (3.1.3) =====")
	// Carica i gruppi di sicurezza dalla configurazione
	securityGroupsFromConfig, err := loadSecurityGroupsFromConfig()
	if err != nil {
		return LogAndReturnError("errore nella decodifica dei gruppi di sicurezza dal file di configurazione", err)
	}

	// Elenca i gruppi di sicurezza da AWS
	describeSGOutput, err := c.EC2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return LogAndReturnError("impossibile elencare i gruppi di sicurezza", err)
	}

	// Passa i dati caricati alla funzione RunSecurityGroupCheck
	if err := RunSecurityGroupCheck(securityGroupsFromConfig, describeSGOutput.SecurityGroups); err != nil {
		return LogAndReturnError("errore durante il controllo dei gruppi di sicurezza", err)
	}

	log.Println("===== Controllo dei gruppi di sicurezza completato =====")

	log.Println("===== Inizio controllo dei bucket S3 (3.1.3) =====")
	if err := c.RunS3BucketCheck(); err != nil {
		return LogAndReturnError("errore durante il controllo dei bucket S3", err)
	}
	log.Println("===== Controllo dei bucket S3 completato =====")

	return nil
}

// RunCheckSeparateDuties esegue il controllo per il requisito NIST 3.1.4
func (c *IAMCheck) RunCheckSeparateDuties() error {
	criticalRoles, err := loadCriticalRolesFromConfig()
	if err != nil {
		return LogAndReturnError("impossibile caricare i ruoli critici dal file di configurazione", err)
	}

	listRolesOutput, err := c.IAMClient.ListRoles(context.TODO(), &iam.ListRolesInput{})
	if err != nil {
		return LogAndReturnError("impossibile elencare i ruoli IAM su AWS", err)
	}

	roleFunctionMap := MapRolesToFunctions(listRolesOutput.Roles, c.IAMClient)

	for _, criticalRole := range criticalRoles {
		if err := VerifyCriticalRoleCompliance(criticalRole, roleFunctionMap); err != nil {
			return err
		}
	}

	log.Println("INFO: Verifica separazione dei compiti completata con successo.")
	return nil
}

// Funzione per eseguire il controllo sui privilegi 3.1.5
func (c *IAMCheck) RunPrivilegeCheck() error {
	// Carica gli utenti e le loro policy dalla configurazione
	usersFromConfig, err := LoadUsersFromConfig()
	if err != nil {
		return LogAndReturnError("impossibile caricare gli utenti dal file di configurazione", err)
	}

	// Verifica i privilegi e le funzioni di sicurezza per ogni utente
	for _, user := range usersFromConfig {
		log.Printf("Verifica dei privilegi per l'utente: %s\n", user.Name)

		// Verifica che ogni funzione di sicurezza corrisponda a una policy assegnata
		for _, sf := range user.SecurityFunctions {
			log.Printf("Verifica della funzione di sicurezza %s per l'utente %s\n", sf, user.Name)

			// Variabile per determinare se è stata trovata una policy corrispondente
			found := false

			// Controlla se c'è una policy che copre la funzione di sicurezza
			for _, policy := range user.Policies {
				log.Printf("Verifica della policy %s per la funzione di sicurezza %s\n", policy, sf)

				if policy == sf {
					found = true
					break
				}
			}

			// Se non è stata trovata alcuna policy corrispondente alla funzione di sicurezza, segnala l'errore
			if !found {
				log.Printf("ERRORE: La funzione di sicurezza %s per l'utente %s non è coperta da alcuna policy\n", sf, user.Name)
				return fmt.Errorf("funzioni di sicurezza non conformi per l'utente %s", user.Name)
			}
		}

	}

	return nil
}

// RunPrivilegeAccountCheck esegue il controllo per il requisito NIST 3.1.6
func (c *IAMCheck) RunPrivilegeAccountCheck() error {
	usersFromConfig, err := LoadUsersFromConfig()
	if err != nil {
		return LogAndReturnError("Impossibile caricare gli utenti dal file di configurazione", err)
	}

	for _, user := range usersFromConfig {
		log.Printf("Verifica dei privilegi per l'utente: %s\n", user.Name)

		// Se l'utente non è privilegiato ma ha funzioni di sicurezza
		if !user.IsPrivileged && len(user.SecurityFunctions) > 0 {
			for _, sf := range user.SecurityFunctions {
				log.Printf("ERRORE: L'utente %s non è privilegiato ma ha accesso alla funzione di sicurezza: %s\n", user.Name, sf)
			}
			return fmt.Errorf("utente %s non privilegiato con accesso a funzioni di sicurezza", user.Name)
		}

		// Se l'utente è privilegiato ma non ha funzioni di sicurezza
		if user.IsPrivileged && len(user.SecurityFunctions) == 0 {
			log.Printf("ERRORE: L'utente privilegiato %s non ha funzioni di sicurezza assegnate\n", user.Name)
			return fmt.Errorf("utente privilegiato %s senza funzioni di sicurezza", user.Name)
		}

		// Verifica che le policy corrispondano alle funzioni di sicurezza
		for _, sf := range user.SecurityFunctions {
			if !ContainsString(user.Policies, sf) {
				log.Printf("ERRORE: La policy %s per l'utente %s non corrisponde alla funzione di sicurezza %s\n", user.Policies, user.Name, sf)
				return fmt.Errorf("funzioni di sicurezza non conformi per l'utente %s", user.Name)
			}
		}
	}

	log.Println("Verifica dei privilegi completata con successo")
	return nil
}

// loadUsersFromConfig carica gli utenti e le relative policy dal file YAML
func LoadUsersFromConfig() (map[string]config.User, error) {
	var usersConfig []config.User
	err := viper.UnmarshalKey("aws.users", &usersConfig)
	if err != nil {
		return nil, fmt.Errorf("errore nella decodifica degli utenti dal file di configurazione: %v", err)
	}

	return MapUsers(usersConfig), nil
}

// loadSecurityGroupsFromConfig carica i gruppi di sicurezza dal file di configurazione
func loadSecurityGroupsFromConfig() ([]config.SecurityGroup, error) {
	var securityGroups []config.SecurityGroup
	err := viper.UnmarshalKey("aws.security_groups", &securityGroups)
	if err != nil {
		return nil, fmt.Errorf("errore nella decodifica dei gruppi di sicurezza dal file di configurazione: %v", err)
	}
	return securityGroups, nil
}

// loadS3BucketsFromConfig carica i bucket S3 dal file di configurazione
func loadS3BucketsFromConfig() ([]config.S3Bucket, error) {
	var s3Buckets []config.S3Bucket
	err := viper.UnmarshalKey("aws.s3_buckets", &s3Buckets)
	if err != nil {
		return nil, fmt.Errorf("errore nella decodifica dei bucket S3 dal file di configurazione: %v", err)
	}
	return s3Buckets, nil
}

// loadCriticalRolesFromConfig carica i ruoli critici dal file di configurazione
func loadCriticalRolesFromConfig() ([]config.CriticalRole, error) {
	var criticalRoles []config.CriticalRole
	err := viper.UnmarshalKey("aws.critical_roles", &criticalRoles)
	if err != nil {
		return nil, fmt.Errorf("errore nella decodifica dei ruoli critici dal file di configurazione: %v", err)
	}
	return criticalRoles, nil
}

// loadAcceptedPoliciesFromConfig carica le policy accettate dal file di configurazione
func loadAcceptedPoliciesFromConfig() ([]string, error) {
	var acceptedPolicies []string
	err := viper.UnmarshalKey("aws.accepted_policies", &acceptedPolicies)
	if err != nil {
		return nil, fmt.Errorf("errore nella decodifica delle policy accettate dal file di configurazione: %v", err)
	}
	return acceptedPolicies, nil
}

// RunPrivilegedFunctionCheck esegue il controllo per il requisito NIST 3.1.7
func (c *IAMCheck) RunPrivilegedFunctionCheck() error {
	// Carica gli utenti dal file di configurazione
	usersFromConfig, err := LoadUsersFromConfig()
	if err != nil {
		return LogAndReturnError("Impossibile caricare gli utenti dal file di configurazione", err)
	}

	for _, user := range usersFromConfig {
		log.Printf("Verifica dei privilegi per l'utente: %s\n", user.Name)

		// Controlla se un utente non privilegiato ha accesso a funzioni privilegiate
		if !user.IsPrivileged && len(user.SecurityFunctions) > 0 {
			for _, sf := range user.SecurityFunctions {
				// Se l'utente non privilegiato ha una funzione di sicurezza, segnala un errore
				log.Printf("ERRORE: L'utente non privilegiato %s ha accesso alla funzione di sicurezza: %s\n", user.Name, sf)
				return fmt.Errorf("utente %s non privilegiato con accesso a funzioni di sicurezza: %s", user.Name, sf)
			}
		}
	}

	// Tutti i controlli sono passati
	log.Println("Verifica delle funzioni privilegiate completata con successo.")
	return nil
}

// LoginAttempt rappresenta un tentativo di accesso
type LoginAttempt struct {
	Username       string
	AttemptTime    time.Time
	IsSuccessful   bool
	FailedAttempts int
	IsLocked       bool
	LockoutTime    time.Time
}

var failedAttempts = map[string]*LoginAttempt{}

// RunLoginAttemptCheck verifica i tentativi di accesso falliti e applica le azioni definite
func (c *IAMCheck) RunLoginAttemptCheck(user string, isSuccess bool, loginPolicy config.LoginPolicy) error {
	now := time.Now()

	// Controlla se l'utente ha già effettuato tentativi di accesso falliti
	if _, exists := failedAttempts[user]; !exists {
		failedAttempts[user] = &LoginAttempt{
			Username:       user,
			AttemptTime:    now,
			IsSuccessful:   isSuccess,
			FailedAttempts: 0,
			IsLocked:       false,
		}
	}

	loginAttempt := failedAttempts[user]

	// Se l'account è bloccato, verifica se deve essere sbloccato
	if loginAttempt.IsLocked {
		if now.Sub(loginAttempt.LockoutTime) > time.Duration(loginPolicy.LockoutDurationMinutes)*time.Minute {
			// Sblocca l'account dopo il periodo di blocco
			loginAttempt.IsLocked = false
			loginAttempt.FailedAttempts = 0
			log.Printf("Account %s sbloccato automaticamente\n", user)
		} else {
			// L'account è ancora bloccato
			log.Printf("Account %s è bloccato fino a %s\n", user, loginAttempt.LockoutTime.Add(time.Duration(loginPolicy.LockoutDurationMinutes)*time.Minute))
			return fmt.Errorf("account %s bloccato", user)
		}
	}

	// Se l'accesso è fallito, incrementa il conteggio
	if !isSuccess {
		loginAttempt.FailedAttempts++
		log.Printf("Tentativo di accesso fallito per l'utente %s. Totale tentativi falliti: %d\n", user, loginAttempt.FailedAttempts)

		// Verifica se il numero massimo di tentativi è stato superato
		if loginAttempt.FailedAttempts >= loginPolicy.MaxUnsuccessfulAttempts {
			// Applica l'azione di blocco
			loginAttempt.IsLocked = true
			loginAttempt.LockoutTime = now

			// Verifica che `ActionOnLockout` sia specificato e applica l'azione
			switch loginPolicy.ActionOnLockout {
			case "lock_account":
				log.Printf("Account %s bloccato per %d minuti\n", user, loginPolicy.LockoutDurationMinutes)
			case "notify_admin":
				log.Printf("Amministratore notificato per il blocco dell'account %s\n", user)
			default:
				log.Printf("Azione sconosciuta per il blocco dell'account %s: %s\n", user, loginPolicy.ActionOnLockout)
				return fmt.Errorf("azione di blocco sconosciuta: %s", loginPolicy.ActionOnLockout)
			}
			return fmt.Errorf("raggiunto il limite di tentativi di accesso falliti per l'utente %s", user)
		}
	} else {
		// Se l'accesso ha successo, resetta il conteggio dei tentativi falliti
		loginAttempt.FailedAttempts = 0
	}

	return nil
}

// RunSessionTimeoutCheck esegue il controllo per il requisito NIST 3.1.10
func (c *IAMCheck) RunSessionTimeoutCheck(cfg aws.Config) error {
	ssmClient := ssm.NewFromConfig(cfg)

	// Log: Inizio controllo delle sessioni attive
	log.Println("Inizio del controllo delle sessioni attive...")

	// Elenca le sessioni attive
	listSessionsInput := &ssm.DescribeSessionsInput{
		State: "Active",
	}

	listSessionsOutput, err := ssmClient.DescribeSessions(context.TODO(), listSessionsInput)
	if err != nil {
		return fmt.Errorf("impossibile elencare le sessioni attive: %v", err)
	}

	// Log: Numero di sessioni attive trovate
	log.Printf("Numero di sessioni attive trovate: %d\n", len(listSessionsOutput.Sessions))

	// Controlla l'inattività di ogni sessione e termina se necessario
	for _, session := range listSessionsOutput.Sessions {
		inactivityDuration := time.Since(*session.StartDate)

		// Log: Durata di inattività per la sessione corrente
		log.Printf("Sessione ID: %s, Inattività: %v\n", *session.SessionId, inactivityDuration)

		// Timeout di inattività di 30 minuti
		if inactivityDuration > time.Duration(30)*time.Minute {
			terminateSessionInput := &ssm.TerminateSessionInput{
				SessionId: session.SessionId,
			}

			// Log: Tentativo di terminare la sessione per inattività
			log.Printf("Tentativo di terminare la sessione %s per inattività...\n", *session.SessionId)

			_, err := ssmClient.TerminateSession(context.TODO(), terminateSessionInput)
			if err != nil {
				return fmt.Errorf("impossibile terminare la sessione %s: %v", *session.SessionId, err)
			}

			// Log: Conferma che la sessione è stata terminata
			log.Printf("Sessione %s terminata con successo per inattività\n", *session.SessionId)
		} else {
			// Log: Sessione ancora attiva e non terminata
			log.Printf("Sessione %s ancora attiva e non terminata per inattività\n", *session.SessionId)
		}
	}

	// Log: Fine del controllo delle sessioni attive
	log.Println("Controllo delle sessioni attive completato.")

	return nil
}

func (c *IAMCheck) RunInactivitySessionCheck(cfg aws.Config, username string) error {
	iamClient := iam.NewFromConfig(cfg)

	log.Printf("Inizio controllo delle policy di sessione IAM per l'utente %s...\n", username)

	listPoliciesInput := &iam.ListAttachedUserPoliciesInput{
		UserName: &username,
	}
	listPoliciesOutput, err := iamClient.ListAttachedUserPolicies(context.TODO(), listPoliciesInput)
	if err != nil {
		return fmt.Errorf("impossibile elencare le policy per l'utente %s: %v", username, err)
	}

	found := false
	for _, policy := range listPoliciesOutput.AttachedPolicies {
		if *policy.PolicyName == "ForceSessionTimeout" {
			found = true
			break
		}
	}

	if !found {
		log.Printf("ERRORE: La policy ForceSessionTimeout non è associata all'utente %s\n", username)
		return fmt.Errorf("policy ForceSessionTimeout non trovata per l'utente %s", username)
	}

	log.Printf("La policy ForceSessionTimeout è stata trovata per l'utente %s\n", username)
	log.Println("Controllo delle policy di sessione IAM completato.")

	return nil
}

// RunRemoteMonitoringCheck esegue il controllo per verificare se VPC Flow Logs e CloudTrail sono abilitati
// Requisito 3.1.20 di NIST SP 800-171
func (c *IAMCheck) RunRemoteMonitoringCheck(cfg aws.Config) error {
	// Inizializza il client CloudTrail
	cloudTrailClient := cloudtrail.NewFromConfig(cfg)

	// Log: Inizio del controllo VPC Flow Logs
	log.Println("Verifica se i VPC Flow Logs sono abilitati...")

	describeFlowLogsInput := &ec2.DescribeFlowLogsInput{}
	flowLogsOutput, err := c.EC2Client.DescribeFlowLogs(context.TODO(), describeFlowLogsInput)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante il recupero dei VPC Flow Logs: %v", err)
		log.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	// Log: Numero di VPC Flow Logs trovati
	log.Printf("Numero di VPC Flow Logs trovati: %d\n", len(flowLogsOutput.FlowLogs))

	// Se nessun VPC Flow Logs è abilitato, restituisci errore
	if len(flowLogsOutput.FlowLogs) == 0 {
		errorMessage := "ERRORE: Nessun VPC Flow Logs abilitato: non conforme"
		log.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	log.Println("SUCCESSO: I VPC Flow Logs sono abilitati e monitorano il traffico.")

	// Log: Inizio del controllo CloudTrail
	log.Println("Verifica se CloudTrail è abilitato e monitorando le connessioni remote...")

	trailStatusInput := &cloudtrail.GetTrailStatusInput{
		Name: aws.String("management-events"), // TODO - ask user
	}

	trailStatusOutput, err := cloudTrailClient.GetTrailStatus(context.TODO(), trailStatusInput)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante il recupero dello stato di CloudTrail: %v", err)
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	// Log: Stato di CloudTrail
	if !*trailStatusOutput.IsLogging {
		errorMessage := "ERRORE: CloudTrail non è abilitato: non conforme"
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	log.Println("SUCCESSO: CloudTrail è abilitato e sta monitorando le connessioni remote.")

	// Log: Fine del controllo
	log.Println("Controllo delle connessioni esterne completato con successo.")

	return nil
}
