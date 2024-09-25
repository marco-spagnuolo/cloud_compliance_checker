package config

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/spf13/viper"
)

// Config contiene tutte le configurazioni dell'applicazione
type Config struct {
	AWS   AWSConfig
	Azure AzureConfig
	GCP   GCPConfig
}

// AWSConfig contiene le configurazioni specifiche per AWS
type AWSConfig struct {
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
	Region    string `mapstructure:"region"`
}

// AzureConfig contiene le configurazioni specifiche per Azure
type AzureConfig struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
}

// GCPConfig contiene le configurazioni specifiche per GCP
type GCPConfig struct {
	ProjectID       string
	CredentialsFile string
}

// AppConfig è la configurazione globale dell'applicazione
var AppConfig Config

func LoadConfig(configFile string) {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	// Usa le variabili d'ambiente
	viper.AutomaticEnv()

	// Leggi il file di configurazione
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Errore nella lettura del file di configurazione: %s", err)
	}

	// Decodifica la configurazione in AppConfig
	if err := viper.Unmarshal(&AppConfig); err != nil {
		log.Fatalf("Impossibile decodificare la configurazione: %v", err)
	}

	// Stampa i valori caricati per debug
	log.Printf("Access Key: %s, Secret Key: %s, Region: %s", AppConfig.AWS.AccessKey, AppConfig.AWS.SecretKey, AppConfig.AWS.Region)
}

// getConfigFileExtension estrae l'estensione del file di configurazione
func getConfigFileExtension(configFile string) string {
	ext := "yaml" // Default
	if len(configFile) > 0 {
		parts := len(configFile)
		if parts > 0 {
			ext = configFile[parts-1:]
		}
	}
	return ext
}

// setDefaultValues imposta i valori di default per la configurazione
func setDefaultValues() {
	viper.SetDefault("General.ScanInterval", 60)
	viper.SetDefault("General.ReportOutput", "reports/output.json")
	viper.SetDefault("AWS.Region", "us-east-1")
}

// bindEnvVariables collega le variabili d'ambiente alle configurazioni
func bindEnvVariables() {
	viper.BindEnv("AWS.AccessKey", "AWS_ACCESS_KEY")
	viper.BindEnv("AWS.SecretKey", "AWS_SECRET_KEY")
	viper.BindEnv("AWS.Region", "AWS_REGION")

	viper.BindEnv("Azure.TenantID", "AZURE_TENANT_ID")
	viper.BindEnv("Azure.ClientID", "AZURE_CLIENT_ID")
	viper.BindEnv("Azure.ClientSecret", "AZURE_CLIENT_SECRET")
	viper.BindEnv("Azure.SubscriptionID", "AZURE_SUBSCRIPTION_ID")

	viper.BindEnv("GCP.ProjectID", "GCP_PROJECT_ID")
	viper.BindEnv("GCP.CredentialsFile", "GCP_CREDENTIALS_FILE")

	viper.BindEnv("General.ScanInterval", "SCAN_INTERVAL")
	viper.BindEnv("General.ReportOutput", "REPORT_OUTPUT")
	viper.BindEnv("General.ControlsFile", "CONTROLS_FILE")
}

// validateConfig verifica che tutte le configurazioni critiche siano impostate correttamente
func validateConfig() {
	if AppConfig.AWS.AccessKey == "" || AppConfig.AWS.SecretKey == "" || AppConfig.AWS.Region == "" {
		log.Fatal("Configurazione AWS incompleta: AccessKey, SecretKey e Region sono obbligatori")
	}

	if AppConfig.GCP.CredentialsFile != "" {
		if _, err := os.Stat(AppConfig.GCP.CredentialsFile); os.IsNotExist(err) {
			log.Fatalf("File delle credenziali GCP non trovato: %s", AppConfig.GCP.CredentialsFile)
		}
	}

	// Aggiungi altre validazioni se necessario
}

var AWSConfigV2 aws.Config

// loadAWSConfig carica la configurazione AWS SDK v2
func loadAWSConfig() {
	var err error
	AWSConfigV2, err = config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(
			aws.NewCredentialsCache(
				credentials.NewStaticCredentialsProvider(AppConfig.AWS.AccessKey, AppConfig.AWS.SecretKey, ""),
			),
		),
		config.WithRegion(AppConfig.AWS.Region),
	)
	if err != nil {
		log.Fatalf("Impossibile caricare la configurazione AWS SDK v2: %v", err)
	}
}
