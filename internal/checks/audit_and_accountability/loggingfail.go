package audit_and_accountability

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
)

// TODO: fix mail
// LoggingFailureCheck struttura per eseguire il controllo dei fallimenti del logging
type LoggingFailureCheck struct {
	CloudTrailClient  *cloudtrail.Client
	SESClient         *ses.Client
	AlertTimePeriod   time.Duration
	AdditionalActions func()
	FromEmail         string // Email mittente
	ToEmail           string // Email destinatario
}

// NewLoggingFailureCheck crea una nuova istanza di LoggingFailureCheck
func NewLoggingFailureCheck(cfg aws.Config, alertTimePeriod time.Duration, additionalActions func(), fromEmail string, toEmail string) *LoggingFailureCheck {
	return &LoggingFailureCheck{
		CloudTrailClient:  cloudtrail.NewFromConfig(cfg),
		SESClient:         ses.NewFromConfig(cfg),
		AlertTimePeriod:   alertTimePeriod,
		AdditionalActions: additionalActions,
		FromEmail:         fromEmail,
		ToEmail:           toEmail,
	}
}

// RunLoggingFailureCheck esegue il controllo per verificare se ci sono stati fallimenti nel processo di logging
func (c *LoggingFailureCheck) RunLoggingFailureCheck() error {
	fmt.Println("Inizio del controllo dei fallimenti del processo di logging...")

	// Controllo lo stato di CloudTrail per verificare eventuali fallimenti
	trailStatusInput := &cloudtrail.GetTrailStatusInput{
		Name: aws.String("management-events"), // Nome del trail di esempio
	}

	trailStatusOutput, err := c.CloudTrailClient.GetTrailStatus(context.TODO(), trailStatusInput)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante il recupero dello stato di CloudTrail: %v", err)
		c.SendEmail(errorMessage)
		return fmt.Errorf("%s", errorMessage)
	}

	// Verifica se ci sono fallimenti nel logging
	if !*trailStatusOutput.IsLogging {
		errorMessage := "ERRORE: Il processo di logging di CloudTrail è fallito."
		c.SendEmail(errorMessage)

		// Esegui azioni aggiuntive definite dall'organizzazione
		c.AdditionalActions()

		return fmt.Errorf("%s", errorMessage)
	}

	// Controlla il tempo di risposta in caso di errore nel logging
	lastFailureTime := trailStatusOutput.LatestDeliveryTime
	if lastFailureTime != nil && time.Since(*lastFailureTime) < c.AlertTimePeriod {
		alertMessage := fmt.Sprintf("AVVISO: Fallimento nel logging rilevato entro l'ultimo periodo definito: %v", *lastFailureTime)
		c.SendEmail(alertMessage)

		// Esegui azioni aggiuntive
		c.AdditionalActions()
	} else {
		fmt.Println("SUCCESSO: Nessun fallimento del logging rilevato nel periodo di monitoraggio.")
	}

	return nil
}

// SendEmail invia una email utilizzando Amazon SES
func (c *LoggingFailureCheck) SendEmail(message string) error {
	fmt.Println("Invio di un'email di notifica...")

	input := &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: []string{c.ToEmail}, // Email destinatario
		},
		Message: &types.Message{
			Body: &types.Body{
				Text: &types.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(message),
				},
			},
			Subject: &types.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String("Allarme di fallimento del logging"),
			},
		},
		Source: aws.String(c.FromEmail), // Email mittente
	}

	_, err := c.SESClient.SendEmail(context.TODO(), input)
	if err != nil {
		errorMessage := fmt.Sprintf("Errore durante l'invio dell'email: %v", err)
		fmt.Println(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	fmt.Println("Email inviata con successo.")
	return nil
}
