package audit_and_accountability

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// TODO: fix cloudwatchlogs
// AuditLogAnalysis gestisce il controllo dei log per attività sospette
type AuditLogAnalysis struct {
	CloudTrailClient   *cloudtrail.Client
	CloudWatchClient   *cloudwatchlogs.Client
	SuspiciousKeywords []string
}

// NewAuditLogAnalysis crea una nuova istanza di AuditLogAnalysis
func NewAuditLogAnalysis(cfg aws.Config, suspiciousKeywords []string) *AuditLogAnalysis {
	return &AuditLogAnalysis{
		CloudTrailClient:   cloudtrail.NewFromConfig(cfg),
		CloudWatchClient:   cloudwatchlogs.NewFromConfig(cfg),
		SuspiciousKeywords: suspiciousKeywords,
	}
}

// RunAuditLogAnalysis esegue il controllo e l'analisi dei log per attività sospette in CloudTrail e CloudWatch Logs
// req 3.3.5
func (a *AuditLogAnalysis) RunAuditLogAnalysis(lg string) error {
	log.Println("Inizio dell'analisi dei log per attività sospette...")

	// Analizza eventi da CloudTrail
	log.Println("Inizio analisi dei log di CloudTrail...")
	err := a.analyzeCloudTrailLogs()
	if err != nil {
		log.Printf("Errore durante l'analisi dei log di CloudTrail: %v\n", err)
		return err
	}
	log.Println("Analisi dei log di CloudTrail completata.")

	// Analizza eventi da CloudWatch Logs
	log.Println("Inizio analisi dei log di CloudWatch Logs...")
	err = a.analyzeCloudWatchLogs(lg)
	if err != nil {
		log.Printf("Errore durante l'analisi dei log di CloudWatch Logs: %v\n", err)
		return err
	}
	log.Println("Analisi dei log di CloudWatch Logs completata.")

	log.Println("Analisi dei log completata con successo.")
	return nil
}

// analyzeCloudTrailLogs analizza i log di CloudTrail per attività sospette
func (a *AuditLogAnalysis) analyzeCloudTrailLogs() error {
	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()

	log.Printf("Recupero eventi di CloudTrail tra %s e %s\n", startTime, endTime)

	input := &cloudtrail.LookupEventsInput{
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	eventsOutput, err := a.CloudTrailClient.LookupEvents(context.TODO(), input)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante il recupero degli eventi di CloudTrail: %v", err)
		log.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	log.Printf("Numero di eventi recuperati da CloudTrail: %d\n", len(eventsOutput.Events))

	// Itera sugli eventi e verifica il contenuto di ciascun record
	for _, event := range eventsOutput.Events {
		log.Printf("\n[CloudTrail] Evento ID: %s\n", *event.EventId)
		log.Printf("  Tipo di evento: %s\n", *event.EventName)
		log.Printf("  Fonte dell'evento: %s\n", *event.EventSource)

		// Controlla se l'evento è sospetto
		if a.isSuspiciousEvent(event) {
			log.Printf("ATTENZIONE: Evento sospetto rilevato in CloudTrail: %s\n", *event.EventName)
		} else {
			log.Println("Evento normale rilevato in CloudTrail.")
		}
	}

	return nil
}

// analyzeCloudWatchLogs analizza i log di CloudWatch Logs per attività sospette
func (a *AuditLogAnalysis) analyzeCloudWatchLogs(logGroupName string) error {
	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()

	log.Printf("Recupero eventi di CloudWatch Logs per il gruppo %s tra %s e %s\n", logGroupName, startTime, endTime)

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroupName),
		StartTime:    aws.Int64(startTime.Unix() * 1000),
		EndTime:      aws.Int64(endTime.Unix() * 1000),
	}

	eventsOutput, err := a.CloudWatchClient.FilterLogEvents(context.TODO(), input)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante il recupero degli eventi di CloudWatch Logs: %v", err)
		log.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	log.Printf("Numero di eventi recuperati da CloudWatch Logs: %d\n", len(eventsOutput.Events))

	// Itera sugli eventi di CloudWatch Logs
	for _, event := range eventsOutput.Events {
		log.Printf("\n[CloudWatch] Evento ID: %s\n", *event.EventId)
		log.Printf("  Contenuto: %s\n", *event.Message)

		// Controlla se l'evento è sospetto
		if a.isSuspiciousMessage(*event.Message) {
			log.Printf("ATTENZIONE: Evento sospetto rilevato in CloudWatch Logs: %s\n", *event.Message)
		} else {
			log.Println("Evento normale rilevato in CloudWatch Logs.")
		}
	}

	return nil
}

// isSuspiciousEvent verifica se un evento di CloudTrail è sospetto in base a parole chiave
func (a *AuditLogAnalysis) isSuspiciousEvent(event types.Event) bool {
	if event.CloudTrailEvent != nil {
		cloudTrailEvent := make(map[string]interface{})
		err := json.Unmarshal([]byte(*event.CloudTrailEvent), &cloudTrailEvent)
		if err == nil {
			// Cerca parole chiave sospette nel CloudTrailEvent
			eventData, _ := json.Marshal(cloudTrailEvent)
			eventStr := string(eventData)
			for _, keyword := range a.SuspiciousKeywords {
				if strings.Contains(eventStr, keyword) {
					log.Printf("Trovata parola chiave sospetta '%s' nell'evento ID: %s\n", keyword, *event.EventId)
					return true
				}
			}
		}
	}
	return false
}

// isSuspiciousMessage verifica se un messaggio di CloudWatch Logs contiene attività sospette
func (a *AuditLogAnalysis) isSuspiciousMessage(message string) bool {
	for _, keyword := range a.SuspiciousKeywords {
		if strings.Contains(strings.ToLower(message), keyword) {
			log.Printf("Trovata parola chiave sospetta '%s' nel messaggio di CloudWatch Logs\n", keyword)
			return true
		}
	}
	return false
}
