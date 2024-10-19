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
	AccessKey                      string                   `mapstructure:"access_key"`
	SecretKey                      string                   `mapstructure:"secret_key"`
	Region                         string                   `mapstructure:"region"`
	Users                          []User                   `mapstructure:"user"`
	AcceptedPolicies               []string                 `mapstructure:"accepted_policies"`
	SecurityGroups                 []SecurityGroup          `mapstructure:"security_groups"`
	S3Buckets                      []S3Bucket               `mapstructure:"s3_buckets"`
	CriticalRoles                  []CriticalRole           `mapstructure:"critical_roles"`
	LoginPolicy                    LoginPolicy              `mapstructure:"login_policy"`
	MissionEssentialConfig         MissionEssentialConfig   `mapstructure:"mission_essential_capabilities"`
	EC2Instances                   []EC2Config              `mapstructure:"ec2_instances"`
	HighRiskTravelConfig           HighRiskTravelConfig     `mapstructure:"high_risk_travel"`
	IdentifierManagement           IdentifierManagement     `mapstructure:"identifier_management"`
	PasswordPolicy                 PasswordPolicy           `mapstructure:"password_policy"`
	AttackerInstance               AttackerInstanceConfig   `mapstructure:"attacker_instance"`
	SnsTopicArn                    string                   `mapstructure:"sns_topic_arn"`
	TestIncidentRensponseFrequency string                   `mapstructure:"test_incident_response_frequency"`
	MaintenanceConfig              MaintenanceConfig        `mapstructure:"maintainance"`
	RiskAssessmentConfig           RiskAssessmentConfig     `mapstructure:"risk_assessment"`
	SecurityAssessmentConfig       SecurityAssessmentConfig `mapstructure:"security_assessment"`
	Protection                     ProtectionConfig         `mapstructure:"protection"`
	Integrity                      IntegrityConfig          `mapstructure:"integrity"`
}

// User represents a user in the configuration
type User struct {
	Name              string   `mapstructure:"name"`
	Policies          []string `mapstructure:"policies"`
	SecurityFunctions []string `mapstructure:"security_functions"`
	IsPrivileged      bool     `mapstructure:"is_privileged"`
	MFARequired       bool     `mapstructure:"mfa_required"`
	ReauthConditions  []string `mapstructure:"reauth_conditions"`
	IdentifierStatus  string   `mapstructure:"identifier_status"`
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
	AuthorizedSoftware []string `mapstructure:"authorized_software"`
	MACAddress         string   `mapstructure:"mac_address"`
}

// HighRiskTravelConfig defines the organization-specific configurations for pre-travel and post-travel actions
type HighRiskTravelConfig struct {
	PreTravelConfig  PreTravelConfig      `mapstructure:"pre_travel"`
	PostTravelChecks PostTravelChecks     `mapstructure:"post_travel"`
	Users            []HighRiskTravelUser `mapstructure:"users"`
}

// HighRiskTravelUser represents a user associated with high-risk travel
type HighRiskTravelUser struct {
	UserID string `mapstructure:"user_id"`
	Name   string `mapstructure:"name"`
	Role   string `mapstructure:"role"`
}

// PostTravelChecks defines the checks that need to be performed when the individual returns from travel
type PostTravelChecks struct {
	CloudTrailCheck  bool `mapstructure:"cloudtrail_check"`
	VerifySecGroups  bool `mapstructure:"verify_sec_groups"`
	VerifyEncryption bool `mapstructure:"verify_encryption"`
}

type PreTravelConfig struct {
	EC2SecurityGroup string `mapstructure:"ec2_security_group"`
	S3Encryption     string `mapstructure:"s3_encryption"`
}

type IdentifierManagement struct {
	AuthorizedRoles           []string `mapstructure:"authorization_roles"`
	ReusePreventionPeriod     string   `mapstructure:"reuse_prevention_period"`
	IdentifierCharacteristics string   `mapstructure:"identifier_characteristics"`
}

type PasswordPolicy struct {
	MinLength        int  `mapstructure:"min_length"`
	RequireNumbers   bool `mapstructure:"require_numbers"`
	RequireSymbols   bool `mapstructure:"require_symbols"`
	RequireUppercase bool `mapstructure:"require_uppercase"`
	RequireLowercase bool `mapstructure:"require_lowercase"`
}

// AttackerInstanceConfig contains the attacker instance configuration
type AttackerInstanceConfig struct {
	AMI            string `mapstructure:"ami"`
	InstanceType   string `mapstructure:"instance_type"`
	KeyName        string `mapstructure:"key_name"`
	SecurityGroup  string `mapstructure:"security_group"`
	SSHUser        string `mapstructure:"ssh_user"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
}

// MaintenanceConfig holds the details related to maintenance operations
type MaintenanceConfig struct {
	ApprovedMaintenanceTools []string            `mapstructure:"approved_maintenance_tools"`
	AccountID                string              `mapstructure:"account_id"`
	BucketName               string              `mapstructure:"bucket_name"`
	GuardDutyDetectorID      string              `mapstructure:"guardduty_detector_id"`
	EC2MonitoredInstances    []EC2Instance       `mapstructure:"ec2_monitored_instances"`
	NonLocalMaintenance      NonLocalMaintenance `mapstructure:"non_local_maintenance"`
	AuthorizedUsers          AuthorizedUsers     `mapstructure:"authorized_users"`
}

// EC2Instance holds the details for an EC2 instance and its monitoring tools
type EC2Instance struct {
	InstanceID      string   `mapstructure:"instance_id"`
	MonitoringTools []string `mapstructure:"monitoring_tools"`
}

// NonLocalMaintainers holds the details of non-local maintainers
type NonLocalMaintenance struct {
	UserNames []string `mapstructure:"user_names"`
}

// AuthorizedUsers holds the details of authorized users
type AuthorizedUsers struct {
	UserNames []string `mapstructure:"user_names"`
}

// RiskAssessmentConfig holds the details related to risk assessment
type RiskAssessmentConfig struct {
	Frequency             string                      `mapstructure:"frequency"`
	SupplyChainVendors    []string                    `mapstructure:"supply_chain_vendors"`
	AssessmentTemplates   []string                    `mapstructure:"assessment_templates"`
	Arn                   string                      `mapstructure:"assessment_template_arn"`
	VulnerabilityScanning VulnerabilityScanningConfig `mapstructure:"vulnerability_scanning"`
}

type VulnerabilityScanningConfig struct {
	Frequency              string              `mapstructure:"frequency"`
	RensponseTime          RensponseTimeConfig `mapstructure:"rensponse_time"`
	ScanOnNewVulnerability bool                `mapstructure:"scan_on_new_vulnerability"`
	AssessmentTemplateArn  string              `mapstructure:"assessment_template_arn"`
}

type RensponseTimeConfig struct {
	Critical string `mapstructure:"critical"`
	High     string `mapstructure:"high"`
	Medium   string `mapstructure:"medium"`
	Low      string `mapstructure:"low"`
}

// SecurityAssessmentConfig holds the details related to security assessment
type SecurityAssessmentConfig struct {
	S3BucketName string `mapstructure:"s3_bucket_information_exchange"`
}

// ProtectionConfig holds the details related to protection
type ProtectionConfig struct {
	ManagedServices       []string `mapstructure:"managed_services"`
	LogGroupName          string   `mapstructure:"cloud_watch_log_group_name"`
	MobileCodes           []string `mapstructure:"mobile_codes"`
	CloudWatchMobileCodes []string `mapstructure:"cloud_watch_mobile_codes"`
}

// IntegrityConfig holds the details related to integrity
type IntegrityConfig struct {
	BucketNames []string `mapstructure:"bucket_names"`
	LambdaName  string   `mapstructure:"lambda_name"`
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
