package audit_and_accountability

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
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

	// Riduzione dei record di audit per l'analisi
	reducedEvents := c.ReduceAuditRecords(eventsOutput.Events)

	// Generazione del report
	err = c.GenerateAuditReport(reducedEvents)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante la generazione del report di audit: %v", err)
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	fmt.Println("Controllo del contenuto dei record di audit completato con successo.")
	return nil
}

// ReduceAuditRecords filtra e riduce i record di audit per l'analisi
func (c *AuditLogCheck) ReduceAuditRecords(events []types.Event) []map[string]interface{} {
	var reducedEvents []map[string]interface{}

	for _, event := range events {
		reducedEvent := map[string]interface{}{
			"EventID":      *event.EventId,
			"EventName":    *event.EventName,
			"EventSource":  *event.EventSource,
			"EventTime":    event.EventTime.String(),
			"EventRegion":  getEventRegion(event),
			"EventOutcome": getEventOutcome(event),
			"Username":     getEventUsername(event),
		}
		reducedEvents = append(reducedEvents, reducedEvent)
	}
	return reducedEvents
}

// GenerateAuditReport genera un report CSV contenente i record di audit ridotti
func (c *AuditLogCheck) GenerateAuditReport(reducedEvents []map[string]interface{}) error {
	// Creazione del file CSV
	file, err := os.Create("audit_report.csv")
	if err != nil {
		return fmt.Errorf("errore durante la creazione del file report: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Scrittura dell'intestazione
	headers := []string{"EventID", "EventName", "EventSource", "EventTime", "EventRegion", "EventOutcome", "Username"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("errore durante la scrittura dell'intestazione del report: %v", err)
	}

	// Scrittura dei record
	for _, event := range reducedEvents {
		record := []string{
			event["EventID"].(string),
			event["EventName"].(string),
			event["EventSource"].(string),
			event["EventTime"].(string),
			event["EventRegion"].(string),
			event["EventOutcome"].(string),
			event["Username"].(string),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("errore durante la scrittura dei record del report: %v", err)
		}
	}

	fmt.Println("Report di audit generato con successo: audit_report.csv")
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
