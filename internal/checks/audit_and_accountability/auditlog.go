package audit_and_accountability

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// AuditLogCheck esegue il controllo del contenuto dei record di audit
type AuditLogCheck struct {
	CloudTrailClient *cloudtrail.Client
	RetentionPeriod  time.Duration
}

// NewAuditLogCheck crea una nuova istanza di AuditLogCheck
// rd è il periodo di retention in giorni
func NewAuditLogCheck(cfg aws.Config, rd int) *AuditLogCheck {
	return &AuditLogCheck{
		CloudTrailClient: cloudtrail.NewFromConfig(cfg),
		RetentionPeriod:  time.Duration(rd) * 24 * time.Hour,
	}
}

// RunAuditLogCheck esegue il controllo per verificare il contenuto dei record di audit
func (c *AuditLogCheck) RunAuditLogCheck() error {
	fmt.Println("Inizio del controllo del contenuto dei record di audit...")

	// Recupera gli eventi di CloudTrail nell'ultimo giorno (24 ore)
	startTime := time.Now().Add(-c.RetentionPeriod)
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

	// Se nessun evento è stato trovato, restituisci un errore
	if len(eventsOutput.Events) == 0 {
		errorMessage := "ERRORE: Nessun evento trovato nei record di audit"
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	// Itera sugli eventi e verifica il contenuto di ciascun record
	for _, event := range eventsOutput.Events {
		fmt.Printf("\nEvento ID: %s\n", *event.EventId)
		fmt.Printf("  Tipo di evento: %s\n", *event.EventName)
		fmt.Printf("  Quando è avvenuto: %s\n", event.EventTime.String())
		fmt.Printf("  Dove è avvenuto: %s\n", getEventRegion(event))
		fmt.Printf("  Fonte dell'evento: %s\n", *event.EventSource)
		fmt.Printf("  Esito dell'evento: %s\n", getEventOutcome(event))
		fmt.Printf("  Identità coinvolta: %s\n", getEventUsername(event))
	}
	if c.RetentionPeriod > 0 {

		// Controllo della conformità della retention
		for _, event := range eventsOutput.Events {
			// Se l'evento è più vecchio del periodo di retention, genera un errore
			if time.Since(*event.EventTime) > c.RetentionPeriod {
				errorMessage := fmt.Sprintf("ERRORE: L'evento ID %s è più vecchio del periodo di retention (%v)", *event.EventId, c.RetentionPeriod)
				fmt.Println(errorMessage)
				return fmt.Errorf(errorMessage)
			}
		}
	}
	fmt.Println("Controllo del contenuto dei record di audit completato con successo.")
	return nil
}

// getEventRegion restituisce la regione in cui è avvenuto l'evento
func getEventRegion(event types.Event) string {
	if event.CloudTrailEvent != nil {
		// Parse CloudTrailEvent JSON per ottenere la regione
		cloudTrailEvent := make(map[string]interface{})
		err := json.Unmarshal([]byte(*event.CloudTrailEvent), &cloudTrailEvent)
		if err == nil {
			if region, ok := cloudTrailEvent["awsRegion"].(string); ok {
				return region
			}
		}
	}
	return "Regione non disponibile"
}

// getEventOutcome restituisce il risultato dell'evento in base a variabili di interesse
func getEventOutcome(event types.Event) string {
	if event.CloudTrailEvent != nil {
		// Parse CloudTrailEvent JSON per ottenere l'esito
		cloudTrailEvent := make(map[string]interface{})
		err := json.Unmarshal([]byte(*event.CloudTrailEvent), &cloudTrailEvent)
		if err == nil {
			if errorCode, ok := cloudTrailEvent["errorCode"].(string); ok {
				return fmt.Sprintf("Fallito con codice errore: %s", errorCode)
			}
		}
	}
	return "Successo"
}

// getEventUsername restituisce il nome utente dell'evento
func getEventUsername(event types.Event) string {
	if event.Username != nil {
		return *event.Username
	}
	return "Identità non disponibile"
}
