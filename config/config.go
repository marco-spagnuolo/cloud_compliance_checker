package config

import (
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	AWS     AWSConfig
	Azure   AzureConfig
	GCP     GCPConfig
	General GeneralConfig
}

type AWSConfig struct {
	AccessKey string
	SecretKey string
	Region    string
}

type AzureConfig struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
}

type GCPConfig struct {
	ProjectID       string
	CredentialsFile string
}

type GeneralConfig struct {
	ScanInterval int
	ReportOutput string
	ControlsFile string
}

var AppConfig Config

func LoadConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}

	err := viper.Unmarshal(&AppConfig)
	if err != nil {
		log.Fatalf("Unable to decode into struct, %v", err)
	}
}
