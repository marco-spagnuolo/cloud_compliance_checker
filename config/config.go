package config

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

// Config contains the global application configuration
type Config struct {
	AWS AWSConfig
}

// AWSConfig contains the AWS configuration
type AWSConfig struct {
	AccessKey        string          `mapstructure:"access_key"`
	SecretKey        string          `mapstructure:"secret_key"`
	Region           string          `mapstructure:"region"`
	User             User            `yaml:"users"`
	AcceptedPolicies []string        `yaml:"accepted_policies"`
	SecurityGroups   []SecurityGroup `mapstructure:"security_groups"`
	S3Buckets        []S3Bucket      `mapstructure:"s3_buckets"`
	CriticalRole     []CriticalRole  `mapstructure:"critical_roles"`
}

// User rappresents a user in the configuration
type User struct {
	Name     string   `yaml:"name"`
	Policies []string `yaml:"policies"`
}

// SecurityGroup rappresents a security group in the configuration
type SecurityGroup struct {
	Name                string `mapstructure:"name"`
	AllowedIngressPorts []int  `mapstructure:"allowed_ingress_ports"`
	AllowedEgressPorts  []int  `mapstructure:"allowed_egress_ports"`
}

// S3Bucket rappresents a S3 bucket in the configuration
type S3Bucket struct {
	Name       string `mapstructure:"name"`
	Encryption string `mapstructure:"encryption"`
}

// CriticalRole rappresents a critical role in the configuration
type CriticalRole struct {
	RoleName           string   `mapstructure:"role_name"`
	SensitiveFunctions []string `mapstructure:"sensitive_functions"`
}

// AppConfig is the global configuration
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
	// print the configuration
	fmt.Printf("Configurazione caricata con successo: %+v", AppConfig)

}
