package audit_and_accountability

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// PrivilegedUser represents a user or role authorized to manage audit logs
type PrivilegedUser struct {
	Username string
	IsAdmin  bool
}

// AuditProtectionCheck esegue il controllo per proteggere i registri di audit e gli strumenti di logging
type AuditProtectionCheck struct {
	CloudTrailClient *cloudtrail.Client
	AuthorizedUsers  []PrivilegedUser
	CurrentUser      PrivilegedUser
}

// NewAuditProtectionCheck crea una nuova istanza di AuditProtectionCheck
func NewAuditProtectionCheck(cfg aws.Config, authorizedUsers []PrivilegedUser, currentUser PrivilegedUser) *AuditProtectionCheck {
	return &AuditProtectionCheck{
		CloudTrailClient: cloudtrail.NewFromConfig(cfg),
		AuthorizedUsers:  authorizedUsers,
		CurrentUser:      currentUser,
	}
}

// RunAuditProtectionCheck esegue il controllo per proteggere i registri di audit e gli strumenti di logging
func (c *AuditProtectionCheck) RunAuditProtectionCheck() error {
	fmt.Println("Inizio del controllo per proteggere i registri di audit e gli strumenti di logging...")

	// Verifica se l'utente corrente è autorizzato a gestire i registri di audit
	if !c.isUserAuthorized() {
		errMessage := fmt.Sprintf("ERRORE: L'utente %s non è autorizzato a gestire i registri di audit", c.CurrentUser.Username)
		fmt.Println(errMessage)
		c.logUnauthorizedAccess()
		return fmt.Errorf(errMessage)
	}

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

	// Itera sugli eventi e verifica se ci sono state modifiche o eliminazioni non autorizzate
	for _, event := range eventsOutput.Events {
		if c.isSensitiveAction(event) {
			if !c.isActionAuthorized(event.Username) {
				errMessage := fmt.Sprintf("ATTENZIONE: L'utente %s ha eseguito un'azione non autorizzata sui registri di audit. Evento ID: %s", *event.Username, *event.EventId)
				fmt.Println(errMessage)
				c.logUnauthorizedAction(event)
				return fmt.Errorf(errMessage)
			}
		}
	}

	fmt.Println("Controllo per proteggere i registri di audit e gli strumenti di logging completato con successo.")
	return nil
}

// isUserAuthorized verifica se l'utente corrente è autorizzato a gestire i registri di audit
func (c *AuditProtectionCheck) isUserAuthorized() bool {
	for _, user := range c.AuthorizedUsers {
		if user.Username == c.CurrentUser.Username && user.IsAdmin {
			return true
		}
	}
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
		return false
	}
	for _, user := range c.AuthorizedUsers {
		if user.Username == *username && user.IsAdmin {
			return true
		}
	}
	return false
}

// logUnauthorizedAccess registra un tentativo di accesso non autorizzato
func (c *AuditProtectionCheck) logUnauthorizedAccess() {
	// Log the unauthorized access attempt to a file
	file, err := os.OpenFile("unauthorized_access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Errore durante l'apertura del file di log: %v", err)
	}
	defer file.Close()

	logger := log.New(file, "", log.LstdFlags)
	logger.Printf("Tentativo di accesso non autorizzato da parte dell'utente %s", c.CurrentUser.Username)
}

// logUnauthorizedAction registra un'azione non autorizzata sui registri di audit
func (c *AuditProtectionCheck) logUnauthorizedAction(event types.Event) {
	// Log the unauthorized action to a file
	file, err := os.OpenFile("unauthorized_actions.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Errore durante l'apertura del file di log: %v", err)
	}
	defer file.Close()

	logger := log.New(file, "", log.LstdFlags)
	logger.Printf("Azione non autorizzata da parte dell'utente %s. Evento ID: %s", *event.Username, *event.EventId)
}
