package main

import (
	"bufio"
	configure "cloud_compliance_checker/config"
	"cloud_compliance_checker/discovery"
	"cloud_compliance_checker/internal/checks/evaluation"
	"cloud_compliance_checker/models"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// loadControls carica i controlli di conformità da un file JSON
func loadControls(filePath string) (models.NISTControls, error) {
	var controls models.NISTControls
	file, err := os.Open(filePath)
	if err != nil {
		return controls, err
	}
	defer file.Close()

	data := bufio.NewReader(file)
	decoder := json.NewDecoder(data)
	err = decoder.Decode(&controls)
	if err != nil {
		return controls, err
	}
	return controls, nil
}

func main() {
	// Definisce un flag --config per specificare il file di configurazione
	configFile := flag.String("config", "", "path to the config file")
	flag.Parse()

	if *configFile == "" {
		log.Fatalf("Please provide a config file using the --config flag")
	}

	// Carica il file di configurazione
	configure.LoadConfig(*configFile)
	log.Printf("Configurazione caricata con successo: %+v", configure.AppConfig)

	// Carica i controlli di conformità dal file JSON
	controls, err := loadControls("config/control.json")
	if err != nil {
		log.Fatalf("Failed to load controls: %v", err)
	}

	// Crea la configurazione AWS utilizzando le credenziali dal file di configurazione
	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(configure.AppConfig.AWS.Region),
		config.WithCredentialsProvider(aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider(
				configure.AppConfig.AWS.AccessKey,
				configure.AppConfig.AWS.SecretKey,
				"",
			),
		)),
	)
	if err != nil {
		log.Fatalf("Unable to load AWS SDK config, %v", err)
	}

	// Inizializza i client AWS per CloudTrail

	cloudTrailClient := cloudtrail.NewFromConfig(awsCfg)

	// Scopre gli asset AWS
	assets := discovery.DiscoverAssets(awsCfg)

	// Valuta gli asset con i controlli di conformità caricati
	results := evaluation.EvaluateAssets(assets, controls, awsCfg, cloudTrailClient)

	// Stampa i risultati della valutazione di conformità
	for _, result := range results {
		fmt.Printf("Asset: %s\n", result.Asset.Name)
		fmt.Printf("Compliance Score: %d\n", result.Score)
		fmt.Println()
	}
}
