package inc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// IncidentReport rappresenta una struttura per memorizzare gli incidenti rilevati.
type IncidentReport struct {
	Timestamp time.Time
	EventName string
	Resource  string
	User      string
	Details   string
}

// LoadCustomConfig carica il profilo specifico per le credenziali nel pacchetto inc
func LoadCustomConfig() (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile("attacker-user")) // Usa il profilo configurato
	if err != nil {
		return aws.Config{}, fmt.Errorf("errore durante il caricamento delle credenziali personalizzate: %v", err)
	}
	return cfg, nil
}

// RunCheck esegue le operazioni solo con il profilo specifico per il pacchetto `inc`
func RunCheck(awsCfg aws.Config) error {
	// Carica la configurazione con il nuovo utente IAM
	cfg, err := LoadCustomConfig()
	if err != nil {
		log.Fatalf("Errore durante il caricamento della configurazione: %v", err)
		return err
	}

	// Step 1: Preparazione dell'ambiente
	cloudTrailClient := cloudtrail.NewFromConfig(awsCfg)
	cloudWatchClient := cloudwatch.NewFromConfig(awsCfg)
	snsClient := sns.NewFromConfig(awsCfg)
	ec2Client := ec2.NewFromConfig(awsCfg)
	ec2ClientAttacker := ec2.NewFromConfig(cfg)

	// Step 2: Tentativo di sblocco dell'istanza da parte dell'attaccante
	instanceID := "i-063bb3f42843d546a"
	err = MoveInstanceToSecurityGroup(ec2ClientAttacker, instanceID, "sg-0117d2e82d65830bd") //default security group
	if err != nil {
		if strings.Contains(err.Error(), "UnauthorizedOperation") {
			unauthorizedError := fmt.Errorf("UnauthorizedOperation: %v", err)
			log.Printf("Incidente rilevato: Operazione non autorizzata dall'utente attacker-user. Dettagli: %v", err)

			// Notifica l'incidente e continua l'esecuzione
			NotifyAndContainIncident(unauthorizedError, snsClient, cloudWatchClient)

			// Aggiungi l'incidente a una lista per gestirlo successivamente
			incident := IncidentReport{
				Timestamp: time.Now(),
				EventName: "UnauthorizedOperation",
				Resource:  instanceID,
				User:      "attacker-user",
				Details:   err.Error(),
			}
			// Analizza e notifica come incidente
			AnalyzeIncidents([]IncidentReport{incident})
			err = NotifyViaSNS(snsClient, "arn:aws:sns:us-east-1:682033472444:IncidentAlert", incident)
			if err != nil {
				log.Fatalf("Errore nell'invio della notifica SNS: %v", err)
				return err
			}
		} else {
			// Se l'errore non riguarda i permessi, interrompe l'esecuzione
			log.Fatalf("Errore durante lo sblocco dell'istanza da parte di attacker-user: %v", err)
			return err
		}
	} else {
		log.Println("Attaccante ha spostato l'istanza nel security group sg-0530b0ccad6da9360 (incidente).")
	}

	// Step 3: Esegue lo sblocco legittimo dell'istanza con l'utente valido
	err = MoveInstanceToSecurityGroup(ec2Client, instanceID, "sg-0117d2e82d65830bd") //default security group
	if err != nil {
		log.Fatalf("Errore durante lo sblocco dell'istanza: %v", err)
		return err
	}
	log.Println("Istanza sbloccata correttamente nel security group sg-0530b0ccad6da9360.")

	// Step 4: Verifica della configurazione di sicurezza
	err = CheckSecuritySetup(cloudTrailClient, cloudWatchClient, snsClient)
	if err != nil {
		log.Fatalf("Errore nella verifica della configurazione di sicurezza: %v", err)
		return err
	}

	// Step 5: Simulazione di un incidente (modifica al Security Group)
	securityGroupID := "sg-00c5015b6c3fa9161" // attacker security group
	err = SimulateSecurityGroupIngress(ec2Client, securityGroupID)
	if err != nil {
		log.Fatalf("Errore durante la simulazione: %v", err)
		return err
	}

	// Step 6: Attendi che CloudTrail registri l'evento
	log.Println("Aspettando che CloudTrail rilevi l'incidente...")
	time.Sleep(180 * time.Second) // Attendere 3 minuti affinché CloudTrail registri l'evento.

	// Step 7: Rilevazione degli incidenti
	incidents, err := DetectIncidents(cloudTrailClient)
	if err != nil {
		log.Fatalf("Errore nella rilevazione degli incidenti: %v", err)
		return err
	}

	// Step 8: Analisi degli incidenti e notifica
	if len(incidents) > 0 {
		AnalyzeIncidents(incidents)
		arn := "arn:aws:sns:us-east-1:682033472444:IncidentAlert"
		for _, incident := range incidents {
			err = NotifyViaSNS(snsClient, arn, incident)
			if err != nil {
				log.Fatalf("Errore nell'invio della notifica SNS: %v", err)
				return err
			}
		}

		// Step 9: Contenimento degli incidenti (Isoliamo l'istanza mettendola nel gruppo di quarantena)
		err = MoveInstanceToSecurityGroup(ec2Client, instanceID, "sg-0ee645f2ff11d765b") // Quarantena
		if err != nil {
			log.Fatalf("Errore nel contenimento dell'incidente: %v", err)
			return err
		}
		log.Println("Istanza isolata nel gruppo di sicurezza quarantena (sg-0ee645f2ff11d765b).")

		// Step 10: Eradicazione e ripristino
		err = EradicateAndRecover(ec2Client, securityGroupID, incidents)
		if err != nil {
			log.Fatalf("Errore nell'eradicazione e ripristino: %v", err)
			return err
		}
	} else {
		log.Println("Nessun incidente rilevato.")
	}
	return nil
}

// NotifyAndContainIncident notifica l'incidente e esegue il contenimento.
func NotifyAndContainIncident(err error, snsClient *sns.Client, cloudWatchClient *cloudwatch.Client) error {
	log.Printf("Notifica incidente di autorizzazione non riuscita: %v", err)

	// Invia una notifica SNS
	arn := "arn:aws:sns:us-east-1:682033472444:IncidentAlert"
	incident := IncidentReport{
		Timestamp: time.Now(),
		EventName: "UnauthorizedOperation",
		Resource:  "EC2 Instance Operation",
		User:      "attacker-user",
		Details:   err.Error(),
	}
	message, _ := json.Marshal(incident)
	_, errSNS := snsClient.Publish(context.TODO(), &sns.PublishInput{
		Message:  aws.String(string(message)),
		TopicArn: aws.String(arn),
	})
	if errSNS != nil {
		log.Printf("Errore nell'invio della notifica SNS: %v", errSNS)
		return errSNS
	}

	// Contenimento (se richiesto)
	return nil
}

// DetectIncidents utilizza CloudTrail per rilevare incidenti basati su tipi di eventi specifici.
func DetectIncidents(cloudTrailClient *cloudtrail.Client) ([]IncidentReport, error) {
	startTime := time.Now().Add(-2 * time.Hour) // Estendere il periodo di rilevamento a 2 ore

	resp, err := cloudTrailClient.LookupEvents(context.TODO(), &cloudtrail.LookupEventsInput{
		StartTime: &startTime,
	})
	if err != nil {
		return nil, fmt.Errorf("impossibile rilevare incidenti: %v", err)
	}

	var incidents []IncidentReport
	for _, event := range resp.Events {
		// Rileva eventi specifici come modifiche ai Security Group o operazioni non autorizzate
		if *event.EventName == "AuthorizeSecurityGroupIngress" || *event.EventName == "DeleteSecurityGroup" || *event.EventName == "CreateUser" || *event.EventName == "UnauthorizedOperation" {
			incident := IncidentReport{
				Timestamp: *event.EventTime,
				EventName: *event.EventName,
				User:      *event.Username,
				Details:   *event.CloudTrailEvent,
			}
			if len(event.Resources) > 0 && event.Resources[0].ResourceName != nil {
				incident.Resource = *event.Resources[0].ResourceName
			} else {
				incident.Resource = "Resource Unknown"
			}
			incidents = append(incidents, incident)
		}
	}

	return incidents, nil
}

// MoveInstanceToSecurityGroup sposta un'istanza nel security group specificato
func MoveInstanceToSecurityGroup(ec2Client *ec2.Client, instanceID string, securityGroupID string) error {
	// Verifica che l'istanza e il security group appartengano alla stessa VPC
	instanceVPC, err := GetInstanceVPC(ec2Client, instanceID)
	if err != nil {
		return fmt.Errorf("errore nel recuperare la VPC dell'istanza: %v", err)
	}

	securityGroupVPC, err := GetSecurityGroupVPC(ec2Client, securityGroupID)
	if err != nil {
		return fmt.Errorf("errore nel recuperare la VPC del security group: %v", err)
	}

	if instanceVPC != securityGroupVPC {
		return fmt.Errorf("istanza e security group appartengono a VPC diverse: %s vs %s", instanceVPC, securityGroupVPC)
	}

	// Sposta l'istanza nel security group specificato
	_, err = ec2Client.ModifyInstanceAttribute(context.TODO(), &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		Groups:     []string{securityGroupID},
	})
	if err != nil {
		return fmt.Errorf("errore durante lo spostamento dell'istanza %s nel security group %s: %v", instanceID, securityGroupID, err)
	}
	return nil
}

// GetInstanceVPC recupera la VPC dell'istanza specificata
func GetInstanceVPC(ec2Client *ec2.Client, instanceID string) (string, error) {
	resp, err := ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return "", fmt.Errorf("errore durante il recupero dell'istanza: %v", err)
	}

	if len(resp.Reservations) == 0 || len(resp.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("istanza %s non trovata", instanceID)
	}

	return *resp.Reservations[0].Instances[0].VpcId, nil
}

// GetSecurityGroupVPC recupera la VPC del security group specificato
func GetSecurityGroupVPC(ec2Client *ec2.Client, securityGroupID string) (string, error) {
	resp, err := ec2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{securityGroupID},
	})
	if err != nil {
		return "", fmt.Errorf("errore durante il recupero del security group: %v", err)
	}

	if len(resp.SecurityGroups) == 0 {
		return "", fmt.Errorf("security group %s non trovato", securityGroupID)
	}

	return *resp.SecurityGroups[0].VpcId, nil
}

// CheckSecuritySetup verifica la configurazione di CloudTrail, CloudWatch e SNS
func CheckSecuritySetup(cloudTrailClient *cloudtrail.Client, cloudWatchClient *cloudwatch.Client, snsClient *sns.Client) error {
	// Verifica che CloudTrail sia attivo
	_, err := cloudTrailClient.DescribeTrails(context.TODO(), &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return fmt.Errorf("errore durante la verifica di CloudTrail: %v", err)
	}
	log.Println("CloudTrail è attivo e funzionante.")

	// Verifica che un allarme CloudWatch sia attivo
	_, err = cloudWatchClient.DescribeAlarms(context.TODO(), &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []string{"UnauthorizedIngressAlarm"},
	})
	if err != nil {
		return fmt.Errorf("errore durante la verifica degli allarmi CloudWatch: %v", err)
	}
	log.Println("CloudWatch Alarms sono configurati correttamente.")

	// Verifica che SNS Topic sia configurato correttamente
	_, err = snsClient.ListTopics(context.TODO(), &sns.ListTopicsInput{})
	if err != nil {
		return fmt.Errorf("errore durante la verifica di SNS: %v", err)
	}
	log.Println("SNS è configurato correttamente.")

	return nil
}

// SimulateSecurityGroupIngress simula una modifica al Security Group aggiungendo una regola di ingresso non autorizzata.
func SimulateSecurityGroupIngress(ec2Client *ec2.Client, securityGroupID string) error {

	// Aggiungi la nuova regola di sicurezza
	_, err := ec2Client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(securityGroupID),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges: []ec2types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("errore durante la simulazione di una modifica al Security Group: %v", err)
	}

	log.Println("Simulazione di modifica al Security Group eseguita.")
	return nil
}

// AnalyzeIncidents logga i dettagli degli incidenti e ritorna un report.
func AnalyzeIncidents(incidents []IncidentReport) {
	for _, incident := range incidents {
		log.Printf("Incident rilevato: %v, Resource: %v, User: %v, Details: %v", incident.EventName, incident.Resource, incident.User, incident.Details)
	}
}

// NotifyViaSNS invia una notifica SNS ai responsabili di sicurezza.
func NotifyViaSNS(snsClient *sns.Client, topicARN string, incident IncidentReport) error {
	message, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("errore nella serializzazione dell'incidente: %v", err)
	}

	_, err = snsClient.Publish(context.TODO(), &sns.PublishInput{
		Message:  aws.String(string(message)),
		TopicArn: aws.String(topicARN),
	})
	if err != nil {
		return fmt.Errorf("impossibile inviare la notifica SNS: %v", err)
	}

	log.Printf("Notifica inviata per l'incidente: %v", incident.EventName)
	return nil
}

// ContainIncident limita l'accesso a una risorsa compromessa.
func ContainIncident(resourceName string, cloudWatchClient *cloudwatch.Client) error {
	_, err := cloudWatchClient.PutMetricAlarm(context.TODO(), &cloudwatch.PutMetricAlarmInput{
		AlarmName:          aws.String("UnauthorizedIngressAlarm"),
		MetricName:         aws.String("NetworkIn"),
		Namespace:          aws.String("AWS/EC2"),
		Statistic:          types.StatisticAverage,
		Threshold:          aws.Float64(0.0),
		ComparisonOperator: types.ComparisonOperatorGreaterThanThreshold,
		Period:             aws.Int32(60),
		EvaluationPeriods:  aws.Int32(1),
		AlarmActions:       []string{"arn:aws:sns:us-west-2:123456789012:NotifyAdmin"},
	})

	if err != nil {
		return fmt.Errorf("impossibile contenere l'incidente: %v", err)
	}

	log.Printf("Azione di contenimento eseguita per la risorsa: %v", resourceName)
	return nil
}

// EradicateAndRecover esegue le azioni per pulire e ripristinare l'ambiente.
func EradicateAndRecover(ec2Client *ec2.Client, securityGroupID string, incidents []IncidentReport) error {
	for _, incident := range incidents {
		log.Printf("Eradicazione in corso per l'incidente: %v", incident.EventName)

		// Supponiamo che l'incidente sia stato causato da una regola di accesso non autorizzata (es: apertura SSH a 0.0.0.0/0 sulla porta 22).
		// Revoca la regola di accesso non autorizzata.
		err := DeleteSecurityGroupRule(ec2Client, securityGroupID, "tcp", 22, "0.0.0.0/0")
		if err != nil {
			log.Printf("Errore durante la revoca della regola di sicurezza: %v", err)
			return err
		}
		log.Println("Regola di accesso non autorizzata revocata con successo.")
	}

	// Aggiungi eventuali ulteriori logiche di ripristino, come ripristinare gruppi di sicurezza o backup.
	log.Println("Eradicazione completata. Ambiente ripristinato.")
	return nil
}

// DeleteSecurityGroupRule elimina una regola di ingresso dal Security Group specificato
func DeleteSecurityGroupRule(ec2Client *ec2.Client, securityGroupID string, protocol string, port int32, cidr string) error {
	_, err := ec2Client.RevokeSecurityGroupIngress(context.TODO(), &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(securityGroupID),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String(protocol),
				FromPort:   aws.Int32(port),
				ToPort:     aws.Int32(port),
				IpRanges: []ec2types.IpRange{
					{
						CidrIp: aws.String(cidr),
					},
				},
			},
		},
	})
	log.Printf("Revocata la regola di sicurezza per %s:%d da %s", protocol, port, cidr)
	if err != nil {
		return fmt.Errorf("errore durante l'eliminazione della regola dal security group: %v", err)
	}

	return nil
}
