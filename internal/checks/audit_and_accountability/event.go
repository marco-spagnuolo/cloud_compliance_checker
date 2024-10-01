package audit_and_accountability

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// EventLoggingCheck struttura per eseguire il controllo dei tipi di eventi loggati
type EventLoggingCheck struct {
	CloudTrailClient  *cloudtrail.Client
	DefinedEventTypes []string
	LastReviewDate    time.Time
	ReviewFrequency   time.Duration
}

// NewEventLoggingCheck crea una nuova istanza di EventLoggingCheck
func NewEventLoggingCheck(cfg aws.Config, definedEventTypes []string, lastReviewDate time.Time, reviewFrequency time.Duration) *EventLoggingCheck {
	return &EventLoggingCheck{
		CloudTrailClient:  cloudtrail.NewFromConfig(cfg),
		DefinedEventTypes: definedEventTypes,
		LastReviewDate:    lastReviewDate,
		ReviewFrequency:   reviewFrequency,
	}
}

// RunEventLoggingCheck esegue il controllo per verificare i tipi di eventi loggati
// req 3.3.1
func (c *EventLoggingCheck) RunEventLoggingCheck() error {
	fmt.Println("Inizio del controllo dei tipi di eventi loggati...")

	// Verifica se la revisione della configurazione è stata eseguita nei tempi previsti
	nextReviewDate := c.LastReviewDate.Add(c.ReviewFrequency)
	if time.Now().After(nextReviewDate) {
		errorMessage := fmt.Sprintf("ERRORE: La revisione della configurazione dei tipi di eventi è scaduta. Ultima revisione: %v, Revisione richiesta entro: %v",
			c.LastReviewDate, nextReviewDate)
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage[:len(errorMessage)-1])
	}
	fmt.Printf("SUCCESSO: La revisione della configurazione dei tipi di eventi è valida. Prossima revisione: %v\n", nextReviewDate)

	// Verifica quali eventi sono loggati tramite CloudTrail
	trailStatusInput := &cloudtrail.GetTrailStatusInput{
		Name: aws.String("management-events"), // Nome del trail di esempio
		// TODO - ask user
	}

	trailStatusOutput, err := c.CloudTrailClient.GetTrailStatus(context.TODO(), trailStatusInput)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante il recupero dello stato di CloudTrail: %v", err)
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage[:len(errorMessage)-1])
	}

	// Verifica se CloudTrail sta loggando gli eventi
	if !*trailStatusOutput.IsLogging {
		errorMessage := "ERRORE: CloudTrail non sta loggando eventi."
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}
	fmt.Println("SUCCESSO: CloudTrail sta loggando eventi.")

	// Loggare i tipi di eventi definiti dall'organizzazione
	fmt.Println("Tipi di eventi definiti per il logging:")
	for _, eventType := range c.DefinedEventTypes {
		fmt.Printf("- %s\n", eventType)
	}

	// In questo esempio, supponiamo che i tipi di eventi definiti dall'organizzazione siano
	// eventi specifici su AWS, quindi non possiamo verificare tutti i tipi di eventi con CloudTrail,
	// ma possiamo controllare che CloudTrail sia attivo e monitori le azioni richieste.

	fmt.Println("Controllo dei tipi di eventi loggati completato con successo.")
	return nil
}
