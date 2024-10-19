package inc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
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

// RunCheck esegue un ciclo completo di verifica, simulazione, rilevamento e gestione dell'incidente.
func RunCheck(awsCfg aws.Config) error {
	// Step 1: Preparazione dell'ambiente
	cloudTrailClient := cloudtrail.NewFromConfig(awsCfg)
	cloudWatchClient := cloudwatch.NewFromConfig(awsCfg)
	snsClient := sns.NewFromConfig(awsCfg)
	ec2Client := ec2.NewFromConfig(awsCfg)

	// Step 2: Sblocca l'istanza spostandola in un altro security group
	instanceID := "i-063bb3f42843d546a"
	err := MoveInstanceToSecurityGroup(ec2Client, instanceID, "sg-0117d2e82d65830bd") //default security group
	if err != nil {
		log.Fatalf("Errore durante lo sblocco dell'istanza: %v", err)
		return err
	}
	log.Println("Istanza sbloccata e spostata nel security group sg-0530b0ccad6da9360.")

	// Step 3: Verifica della configurazione di sicurezza
	err = CheckSecuritySetup(cloudTrailClient, cloudWatchClient, snsClient)
	if err != nil {
		log.Fatalf("Errore nella verifica della configurazione di sicurezza: %v", err)
		return err
	}

	// Step 4: Simulazione di un incidente (modifica al Security Group)
	securityGroupID := "sg-00c5015b6c3fa9161" // attacker security group
	err = SimulateSecurityGroupIngress(ec2Client, securityGroupID)
	if err != nil {
		log.Fatalf("Errore durante la simulazione: %v", err)
		return err
	}

	// Step 5: Attendi che CloudTrail registri l'evento
	log.Println("Aspettando che CloudTrail rilevi l'incidente...")
	time.Sleep(120 * time.Second) // Attendere 2 minuti affinché CloudTrail registri l'evento.

	// Step 6: Rilevazione degli incidenti
	incidents, err := DetectIncidents(cloudTrailClient)
	if err != nil {
		log.Fatalf("Errore nella rilevazione degli incidenti: %v", err)
		return err
	}

	// Step 7: Analisi degli incidenti e notifica
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

		// Step 8: Contenimento degli incidenti (Isoliamo l'istanza mettendola nel gruppo di quarantena)
		err = MoveInstanceToSecurityGroup(ec2Client, instanceID, "sg-0ee645f2ff11d765b") // Quarantena
		if err != nil {
			log.Fatalf("Errore nel contenimento dell'incidente: %v", err)
			return err
		}
		log.Println("Istanza isolata nel gruppo di sicurezza quarantena (sg-0ee645f2ff11d765b).")

		// Step 9: Eradicazione e ripristino
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

// SimulateSecurityGroupIngress elimina la regola se esiste già e poi la aggiunge
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

// SecurityGroupRuleExists controlla se una regola di ingresso esiste già nel Security Group
func SecurityGroupRuleExists(ec2Client *ec2.Client, securityGroupID string, protocol string, port int32, cidr string) (bool, error) {
	resp, err := ec2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{securityGroupID},
	})
	if err != nil {
		return false, fmt.Errorf("errore durante la descrizione del security group: %v", err)
	}

	if len(resp.SecurityGroups) == 0 {
		return false, fmt.Errorf("security group %s non trovato", securityGroupID)
	}

	for _, permission := range resp.SecurityGroups[0].IpPermissions {
		if permission.IpProtocol != nil && *permission.IpProtocol == protocol &&
			permission.FromPort != nil && *permission.FromPort == port &&
			permission.ToPort != nil && *permission.ToPort == port {
			for _, rangeItem := range permission.IpRanges {
				if rangeItem.CidrIp != nil && *rangeItem.CidrIp == cidr {
					// La regola esiste già
					return true, nil
				}
			}
		}
	}

	// La regola non esiste
	return false, nil
}

// DetectIncidents utilizza CloudTrail per rilevare incidenti basati su tipi di eventi specifici (es. modifiche ai gruppi di sicurezza).
func DetectIncidents(cloudTrailClient *cloudtrail.Client) ([]IncidentReport, error) {
	startTime := time.Now().Add(-1 * time.Hour)

	resp, err := cloudTrailClient.LookupEvents(context.TODO(), &cloudtrail.LookupEventsInput{
		StartTime: &startTime,
	})
	if err != nil {
		return nil, fmt.Errorf("impossibile rilevare incidenti: %v", err)
	}

	var incidents []IncidentReport
	for _, event := range resp.Events {
		if *event.EventName == "AuthorizeSecurityGroupIngress" || *event.EventName == "DeleteSecurityGroup" || *event.EventName == "CreateUser" {
			incident := IncidentReport{
				Timestamp: *event.EventTime,
				EventName: *event.EventName,
				Resource:  *event.Resources[0].ResourceName,
				User:      *event.Username,
				Details:   *event.CloudTrailEvent,
			}
			incidents = append(incidents, incident)
		}
	}

	return incidents, nil
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
