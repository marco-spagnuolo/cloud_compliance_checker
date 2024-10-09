package incident_response

import (
	"cloud_compliance_checker/config"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// IncidentResponseTest simula un test della capacità di risposta agli incidenti
func IncidentResponseTest(cfg aws.Config) error {
	// Step 1: Determinare la frequenza del test
	frequency := config.AppConfig.AWS.TestIncidentRensponseFrequency
	fmt.Printf("Starting Incident Response Test with frequency: %d\n", frequency)

	// Step 2: Eseguire la simulazione del test di risposta all'incidente
	fmt.Println("Simulating incident response capability...")
	testResults, err := simulateIncidentResponseProcess()
	if err != nil {
		return fmt.Errorf("incident response test failed: %v", err)
	}

	// Step 3: Raccolta e registrazione dei risultati
	fmt.Println("Collecting and recording test results...")
	err = recordTestResults(testResults)
	if err != nil {
		return fmt.Errorf("failed to record test results: %v", err)
	}

	// Step 4: Inviare una notifica di completamento del test tramite SNS
	alertMessage := fmt.Sprintf("Incident response test completed with frequency: %s. Results: %s", frequency, testResults.Status)
	fmt.Printf("Sending SNS alert with message: %s\n", alertMessage)
	err = SendTestAlert(cfg, alertMessage)
	if err != nil {
		return fmt.Errorf("failed to send SNS alert: %v", err)
	}

	fmt.Println("Incident Response Test completed successfully.")
	return nil
}

// simulateIncidentResponseProcess simula un processo di risposta all'incidente
func simulateIncidentResponseProcess() (*TestResults, error) {
	// Simuliamo il processo di risposta all'incidente con un mock
	fmt.Println("Running incident response simulation...")
	startTime := time.Now()

	// Simulazione di test (qui puoi aggiungere processi più complessi, come rilevamento e contenimento)
	time.Sleep(2 * time.Second) // Simulazione di un ritardo per la risposta
	status := "success"         // Status del test, potrebbe essere "failed" se rileviamo errori

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Risultati del test
	testResults := &TestResults{
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		Status:    status,
	}

	return testResults, nil
}

// TestResults rappresenta i risultati del test
type TestResults struct {
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Status    string        `json:"status"`
}

// recordTestResults registra i risultati del test in un file JSON
func recordTestResults(results *TestResults) error {
	fileName := "incident_response_test_results.json"
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create test results file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(results)
	if err != nil {
		return fmt.Errorf("failed to encode test results to JSON: %v", err)
	}

	fmt.Printf("Test results saved to file: %s\n", fileName)
	return nil
}

// SendTestAlert invia un alert SNS con lo stato del test
func SendTestAlert(cfg aws.Config, message string) error {
	topicArn := config.AppConfig.AWS.SnsTopicArn
	fmt.Printf("Sending SNS alert with message: %s\n", message)
	fmt.Printf("SNS topic ARN: %s\n", topicArn)
	if topicArn == "" {
		return fmt.Errorf("SNS topic ARN not found in configuration")
	}
	snsClient := sns.NewFromConfig(cfg)

	_, err := snsClient.Publish(context.TODO(), &sns.PublishInput{
		Message:  &message,
		TopicArn: &topicArn,
	})
	if err != nil {
		return fmt.Errorf("failed to send SNS alert: %v", err)
	}
	return nil
}
