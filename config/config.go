package config

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/viper"
)

// Config contiene tutte le configurazioni dell'applicazione
type Config struct {
	AWS AWSConfig
}

// AWSConfig contiene le configurazioni specifiche per AWS
type AWSConfig struct {
	AccessKey        string          `mapstructure:"access_key"`
	SecretKey        string          `mapstructure:"secret_key"`
	Region           string          `mapstructure:"region"`
	User             User            `yaml:"users"`
	AcceptedPolicies []string        `yaml:"accepted_policies"`
	SecurityGroups   []SecurityGroup `yaml:"security_groups"`
	S3Buckets        []S3Bucket      `yaml:"s3_buckets"`
}
type User struct {
	Name     string   `yaml:"name"`
	Policies []string `yaml:"policies"`
}

// SecurityGroup rappresenta un gruppo di sicurezza dal file di configurazione
type SecurityGroup struct {
	Name                string `yaml:"name"`
	AllowedIngressPorts []int  `yaml:"allowed_ingress_ports"`
	AllowedEgressPorts  []int  `yaml:"allowed_egress_ports"`
}

// S3Bucket rappresenta un bucket S3 dal file di configurazione
type S3Bucket struct {
	Name       string `yaml:"name"`
	Encryption string `yaml:"encryption"`
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

}

var AWSConfigV2 aws.Config

// loadConfigResourcesFromYAML carica gruppi di sicurezza e bucket S3 dal file di configurazione
func loadConfigResourcesFromYAML() (map[string]SecurityGroup, map[string]S3Bucket, error) {
	viper.SetConfigFile("cred.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("errore nella lettura del file di configurazione: %v", err)
	}

	var securityGroupsConfig []SecurityGroup
	err = viper.UnmarshalKey("aws.security_groups", &securityGroupsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("errore nella decodifica dei gruppi di sicurezza: %v", err)
	}

	var s3BucketsConfig []S3Bucket
	err = viper.UnmarshalKey("aws.s3_buckets", &s3BucketsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("errore nella decodifica dei bucket S3: %v", err)
	}

	sgMap := make(map[string]SecurityGroup)
	for _, sg := range securityGroupsConfig {
		sgMap[sg.Name] = sg
	}

	s3Map := make(map[string]S3Bucket)
	for _, bucket := range s3BucketsConfig {
		s3Map[bucket.Name] = bucket
	}

	return sgMap, s3Map, nil
}
