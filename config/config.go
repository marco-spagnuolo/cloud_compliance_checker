package config

import (
	"log"

	"github.com/spf13/viper"
)

// Config contains the global application configuration
type Config struct {
	AWS AWSConfig
}

// AWSConfig contains the AWS configuration
type AWSConfig struct {
	AccessKey              string                 `mapstructure:"access_key"`
	SecretKey              string                 `mapstructure:"secret_key"`
	Region                 string                 `mapstructure:"region"`
	User                   []User                 `mapstructure:"users"`
	AcceptedPolicies       []string               `mapstructure:"accepted_policies"`
	SecurityGroups         []SecurityGroup        `mapstructure:"security_groups"`
	S3Buckets              []S3Bucket             `mapstructure:"s3_buckets"`
	CriticalRole           []CriticalRole         `mapstructure:"critical_roles"`
	LoginPolicy            LoginPolicy            `mapstructure:"login_policy"`
	MissionEssentialConfig MissionEssentialConfig `mapstructure:"mission_essential_capabilities"`
	EC2Instances           []EC2Config            `mapstructure:"ec2_instances"` // List of EC2 instance configurations
}

// User rappresents a user in the configuration
type User struct {
	Name              string   `mapstructure:"name"`
	Policies          []string `mapstructure:"policies"`
	SecurityFunctions []string `mapstructure:"security_functions"`
	IsPrivileged      bool     `mapstructure:"is_privileged"`
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

// LoginPolicy rappresenta la politica di gestione dei tentativi di accesso falliti
type LoginPolicy struct {
	MaxUnsuccessfulAttempts int    `mapstructure:"max_unsuccessful_attempts"`
	LockoutDurationMinutes  int    `mapstructure:"lockout_duration_minutes"`
	ActionOnLockout         string `mapstructure:"action_on_lockout"`
}

// MissionEssentialConfig represents mission-essential functions, ports, protocols, and services
type MissionEssentialConfig struct {
	Functions []string `mapstructure:"functions"`
	Ports     []string `mapstructure:"ports"`
	Protocols []string `mapstructure:"protocols"`
	Services  []string `mapstructure:"services"`
}

// EC2Config represents configuration for each EC2 instance, including authorized software.
type EC2Config struct {
	InstanceID         string   `mapstructure:"instance_id"`
	AuthorizedSoftware []string `mapstructure:"authorized_software"` // List of authorized software for this EC2 instance
}

// AppConfig is the global configuration
var AppConfig Config

func LoadConfig(configFile string) {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Errore nella lettura del file di configurazione: %s", err)
	}

	if err := viper.Unmarshal(&AppConfig); err != nil {
		log.Fatalf("Impossibile decodificare la configurazione: %v", err)
	}
	//fmt.Printf("Configurazione caricata con successo: %+v", AppConfig)

}
