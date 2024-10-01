package audit_and_accountability

import (
	"context"
	"fmt"
	"os"
	"time"

	"cloud_compliance_checker/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// AuditProtectionCheck esegue il controllo per proteggere i registri di audit e gli strumenti di logging
type AuditProtectionCheck struct {
	CloudTrailClient *cloudtrail.Client
	CurrentUser      string
	AuthorizedUsers  []config.User
}

// NewAuditProtectionCheck crea una nuova istanza di AuditProtectionCheck
func NewAuditProtectionCheck(cfg aws.Config, currentUser string) *AuditProtectionCheck {
	// Load authorized users directly from the configuration
	fmt.Println("Caricamento degli utenti autorizzati dalla configurazione")
	authorizedUsers := getAuthorizedUsers()

	return &AuditProtectionCheck{
		CloudTrailClient: cloudtrail.NewFromConfig(cfg),
		CurrentUser:      currentUser,
		AuthorizedUsers:  authorizedUsers,
	}
}

// RunAuditProtectionCheck esegue il controllo per proteggere i registri di audit e gli strumenti di logging
func (c *AuditProtectionCheck) RunAuditProtectionCheck() error {
	fmt.Println("Inizio del controllo per proteggere i registri di audit e gli strumenti di logging...")

	// Verifica se l'utente corrente è autorizzato a gestire i registri di audit
	if !c.isUserAuthorized() {
		errMessage := fmt.Sprintf("ERRORE: L'utente %s non è autorizzato a gestire i registri di audit", c.CurrentUser)
		fmt.Println(errMessage)
		c.logUnauthorizedAccess()
		return fmt.Errorf(errMessage)
	}

	fmt.Println("Utente autorizzato, recupero degli eventi di CloudTrail per ulteriori ispezioni")

	// Recupera gli eventi di CloudTrail per controllare eventuali modifiche non autorizzate
	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()

	input := &cloudtrail.LookupEventsInput{
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	eventsOutput, err := c.CloudTrailClient.LookupEvents(context.TODO(), input)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante il recupero degli eventi di CloudTrail: %v", err)
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	fmt.Printf("Recuperati %d eventi di CloudTrail per l'ispezione\n", len(eventsOutput.Events))

	// Itera sugli eventi e verifica se ci sono state modifiche o eliminazioni non autorizzate
	for _, event := range eventsOutput.Events {
		if c.isSensitiveAction(event) {
			fmt.Printf("Azione sensibile rilevata: %s eseguita da %s\n", *event.EventName, *event.Username)
			if !c.isActionAuthorized(event.Username) {
				errMessage := fmt.Sprintf("ATTENZIONE: L'utente %s ha eseguito un'azione non autorizzata. Evento ID: %s", *event.Username, *event.EventId)
				fmt.Println(errMessage)
				c.logUnauthorizedAction(event)
				return fmt.Errorf(errMessage)
			}
			fmt.Printf("Azione sensibile di %s autorizzata\n", *event.Username)
		}
	}

	fmt.Println("Controllo per proteggere i registri di audit e gli strumenti di logging completato con successo.")
	return nil
}

// isUserAuthorized verifica se l'utente corrente è autorizzato a gestire i registri di audit
func (c *AuditProtectionCheck) isUserAuthorized() bool {
	fmt.Printf("Verifica se l'utente %s è autorizzato\n", c.CurrentUser)
	for _, user := range c.AuthorizedUsers {
		if user.Name == c.CurrentUser && user.IsPrivileged {
			fmt.Printf("L'utente %s è autorizzato\n", c.CurrentUser)
			return true
		}
	}
	fmt.Printf("L'utente %s non è autorizzato\n", c.CurrentUser)
	return false
}

// isSensitiveAction verifica se l'evento rappresenta un'azione sensibile sui registri di audit (modifica o eliminazione)
func (c *AuditProtectionCheck) isSensitiveAction(event types.Event) bool {
	sensitiveActions := []string{"DeleteTrail", "StopLogging", "UpdateTrail", "PutEventSelectors", "RemoveTags"}
	for _, action := range sensitiveActions {
		if *event.EventName == action {
			return true
		}
	}
	return false
}

// isActionAuthorized verifica se l'utente che ha eseguito l'azione è autorizzato
func (c *AuditProtectionCheck) isActionAuthorized(username *string) bool {
	if username == nil {
		fmt.Println("L'evento non ha un nome utente associato")
		return false
	}
	fmt.Printf("Verifica se l'azione eseguita dall'utente %s è autorizzata\n", *username)
	for _, user := range c.AuthorizedUsers {
		if user.Name == *username && user.IsPrivileged {
			fmt.Printf("L'utente %s è autorizzato a eseguire l'azione\n", *username)
			return true
		}
	}
	fmt.Printf("L'utente %s non è autorizzato a eseguire l'azione\n", *username)
	return false
}

// logUnauthorizedAccess registra un tentativo di accesso non autorizzato
func (c *AuditProtectionCheck) logUnauthorizedAccess() {
	// Log the unauthorized access attempt to a file
	fmt.Println("Registrazione del tentativo di accesso non autorizzato")
	file, err := os.OpenFile("unauthorized_access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Errore durante l'apertura del file di log per accessi non autorizzati: %v\n", err)
		return
	}
	defer file.Close()

	logger := fmt.Sprintf("Tentativo di accesso non autorizzato da parte dell'utente %s\n", c.CurrentUser)
	file.WriteString(logger)
}

// logUnauthorizedAction registra un'azione non autorizzata sui registri di audit
func (c *AuditProtectionCheck) logUnauthorizedAction(event types.Event) {
	// Log the unauthorized action to a file
	fmt.Println("Registrazione di un'azione non autorizzata")
	file, err := os.OpenFile("unauthorized_actions.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Errore durante l'apertura del file di log per azioni non autorizzate: %v\n", err)
		return
	}
	defer file.Close()

	logger := fmt.Sprintf("Azione non autorizzata da parte dell'utente %s. Evento ID: %s\n", *event.Username, *event.EventId)
	file.WriteString(logger)
}

// getAuthorizedUsers restituisce l'elenco degli utenti privilegiati (autorizzati)
func getAuthorizedUsers() []config.User {
	fmt.Println("Recupero degli utenti autorizzati dalla configurazione")
	var authorizedUsers []config.User

	// Iterate through users in the loaded configuration and filter privileged users
	for _, user := range config.AppConfig.AWS.User {
		if user.IsPrivileged {
			authorizedUsers = append(authorizedUsers, user)
		}
	}

	fmt.Printf("Trovati %d utenti autorizzati\n", len(authorizedUsers))
	return authorizedUsers
}
