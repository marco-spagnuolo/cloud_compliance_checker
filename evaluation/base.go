package evaluation

import (
	"cloud_compliance_checker/internal/checks/protection"
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

// EvaluateAssets evaluates all assets and returns the compliance results
func EvaluateAssets(controls models.NISTControls,
	cfg aws.Config, cloudTrailClient *cloudtrail.Client) int {
	fmt.Println("=========================================")

	// Separator for readability
	fmt.Println("===== Compliance Evaluation Results =====")

	score := checkInstance(controls, cfg, cloudTrailClient)

	return score
}

// CheckInstance runs all compliance checks on the given instance (SINGLE INSTANCE) and returns the total score
func checkInstance(controls models.NISTControls, cfg aws.Config, cloudTrailClient *cloudtrail.Client) int {
	svc := configservice.NewFromConfig(cfg)
	score := 110

	for _, control := range controls.Controls {
		fmt.Printf("\n")
		fmt.Printf("\n*Control: %s - %s\n", control.ID, control.Description)
		fmt.Printf("\n")

		for _, criteria := range control.Criteria {
			result := evaluateCriteria(svc, criteria, cfg, cloudTrailClient)

			// Print results for each check in a readable format
			fmt.Printf("\n")
			fmt.Printf("  Check: %s\n", criteria.CheckFunction)
			fmt.Printf("    Description: %s\n", criteria.Description)
			fmt.Printf("    Result: %s\n", result.Status)
			fmt.Printf("    Impact: %d\n", criteria.Value)

			score -= result.Impact
		}
	}

	return score
}

// evaluateCriteria evaluates the criteria for a given instance and returns the compliance result
func evaluateCriteria(svc *configservice.Client, criteria models.Criteria,
	cfg aws.Config, cloudTrailClient *cloudtrail.Client) models.ComplianceResult {
	var result models.ComplianceResult
	//check := policy.NewIAMCheck(cfg)

	switch criteria.CheckFunction {
	// case "CheckUsersPolicies":
	// 	err := check.RunCheckPolicies()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 	}
	// case "CheckAcceptedPolicies":
	// 	err := check.RunCheckAcceptedPolicies()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckCUIFlow":
	// 	err := check.RunCheckCUIFlow()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckSeparateDuties":
	// 	err := check.RunCheckSeparateDuties()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckLeastPrivilege":
	// 	err := check.RunPrivilegeCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckPrivilegedAccounts":
	// 	err := check.RunPrivilegeAccountCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckPreventPrivilegedFunctions":
	// 	err := check.RunPrivilegedFunctionCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckLogonAttempts":
	// 	// Carica gli utenti dal file di configurazione
	// 	usersFromConfig, err := iampolicy.LoadUsersFromConfig()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: "Errore nel caricamento degli utenti",
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}

	// 	// Cerca specificamente l'utente marco_admin
	// 	user, ok := usersFromConfig["marco_admin"]
	// 	if !ok {
	// 		result = models.ComplianceResult{
	// 			Description: "Utente marco_admin non trovato nella configurazione",
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    "Impossibile eseguire il controllo senza l'utente marco_admin",
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}

	// 	// Carica la politica di accesso definita nel file di configurazione
	// 	loginPolicy := config.AppConfig.AWS.LoginPolicy

	// 	// Esegui il controllo del tentativo di accesso per marco_admin
	// 	err = check.RunLoginAttemptCheck(user.Name, false, loginPolicy) // Simula un tentativo fallito
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckSessionLock":
	// 	err := check.RunSessionTimeoutCheck(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckSessionTermination":
	// 	err := check.RunInactivitySessionCheck(cfg, "marco_admin")
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckRemoteAccessControl":
	// 	remoteAccessCheck := iampolicy.NewRemoteAccessCheck(cfg)
	// 	err := remoteAccessCheck.RunRemoteAccessCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckExternalSystemConnections":
	// 	err := check.RunRemoteMonitoringCheck(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckAuditLogs":
	// 	aa := audit_and_accountability.NewEventLoggingCheck(cfg, []string{"AWS_EC2"}, time.Now(), 30)
	// 	err := aa.RunEventLoggingCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckUserTraceability":
	// 	aa := audit_and_accountability.NewAuditLogCheck(cfg, 0)
	// 	err := aa.RunAuditLogCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckLoggedEventsRetention":
	// 	aa := audit_and_accountability.NewAuditLogCheck(cfg, 90) // TODO - ask user
	// 	err := aa.RunAuditLogCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckLoggingFailure":
	// 	lfc := audit_and_accountability.NewLoggingFailureCheck(cfg, 24*time.Hour, nil, "mittente@example.com", "destinatario@example.com")
	// 	err := lfc.RunLoggingFailureCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckAuditLogAnalysis":
	// 	aa := audit_and_accountability.NewAuditLogAnalysis(cfg, []string{"failed", "unauthorized", "error"})
	// 	logGroupName := "/aws/lambda/my-function"
	// 	err := aa.RunAuditLogAnalysis(logGroupName)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Audit log analysis check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckAuditRecordReduction":
	// 	aa := audit_and_accountability.NewAuditLogCheck(cfg, 30) // 30-day retention for this check
	// 	err := aa.RunAuditLogCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckTimeSynchronization":
	// 	// print the current time and the zone it is in
	// 	fmt.Println("Current Time in UTC: ", time.Now().UTC())
	// 	fmt.Println("Clock in logs are synchronized with the system clock")

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckAuditSecurity":
	// 	aa := audit_and_accountability.NewAuditProtectionCheck(cfg, "marco_admin")
	// 	err := aa.RunAuditProtectionCheck()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckBaselineConfigurations":
	// 	err := config_management.RunAWSBaselineCheck(cfg, &config.AppConfig.AWS)

	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result
	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckEssentialCapabilities":
	// 	err := config_management.RunAWSResourceReview(cfg)

	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckAuthorizedSoftware":
	// 	err := config_management.RunSoftwareExecutionCheck(cfg)

	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckInformationLocation":
	// 	assets := discovery.DiscoverAssets(cfg)

	// 	config_management.DocumentDiscoveredAssets(assets)
	// 	err := config_management.DisplayCUIComponents()
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckHighRiskTravel":
	// 	err := config_management.CheckHighRiskTravelCompliance(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckUserIdentification":
	// 	err := id_auth.RunComplianceCheck(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckDeviceIdentification":
	// 	err := id_auth.CheckMac(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckMFA":
	// 	// Create IAM client
	// 	iamClient := iam.NewFromConfig(cfg)

	// 	// Enforce MFA for users
	// 	err := id_auth.EnforceMFAForUsers(iamClient)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	//	}
	// case "CheckRRA":
	// 	// Create IAM client
	// 	iamClient := iam.NewFromConfig(cfg)

	// 	// Enforce MFA for users
	// 	err := id_auth.EnforceMFAForUsers(iamClient)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckIAM":
	// 	// Create IAM client

	// 	// Enforce MFA for users
	// 	err := id_auth.CheckIAM(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}
	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckPasswordComplexity":
	// 	// Create IAM client

	// 	// Enforce MFA for users
	// 	err := id_auth.CheckPasswordPolicyEnforcement(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckIRHandling":

	// 	err := incident_response.CheckIncidentHandling(cfg, false)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckIRHandlingAndStore":

	// 	err := incident_response.CheckIncidentHandling(cfg, true)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckIRTesting":

	// 	err := incident_response.SimulateRealIncident(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckMaintainanceTools":

	// 	err := maintenance.RunMonitorCheck(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckNonLocalMaintainance":

	// 	err := maintenance.CheckNonLocalMaintenanceCompliance(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckMaintainancePersonnel":

	// 	err := maintenance.CheckMaintenanceAuthorization(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckRA":

	// 	err := risk_assesment.ScheduleRiskAssessment(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckMonitorAndScanning":

	// 	err := risk_assesment.CheckAndStartVulnerabilityScan(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckRiskRensponse":

	// 	err := risk_assesment.VerifyAutoRiskAssessment(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckSA":

	// 	err := audit.CheckMonitoringTools(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}
	// case "CheckCM":

	// 	err := audit.CheckMonitoringTools(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	// case "CheckBP":

	// 	err := protection.VerifyComponents(cfg)
	// 	if err != nil {
	// 		result = models.ComplianceResult{
	// 			Description: criteria.Description,
	// 			Status:      "NOT COMPLIANT",
	// 			Response:    err.Error(),
	// 			Impact:      criteria.Value,
	// 		}
	// 		fmt.Printf("\n[ERROR]: %v\n", err)
	// 		return result

	// 	}

	// 	result = models.ComplianceResult{
	// 		Description: criteria.Description,
	// 		Status:      "COMPLIANT",
	// 		Response:    "Check passed",
	// 		Impact:      0,
	// 	}

	case "CheckISR":

		err := protection.SecureAWSResources(cfg)
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			fmt.Printf("\n[ERROR]: %v\n", err)
			return result

		}

		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      0,
		}
	case "CheckNetworkTraffic":

		err := protection.CheckDenyByDefaultSecurityGroup(cfg)
		if err != nil {
			result = models.ComplianceResult{
				Description: criteria.Description,
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			fmt.Printf("\n[ERROR]: %v\n", err)
			return result

		}

		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "COMPLIANT",
			Response:    "Check passed",
			Impact:      0,
		}
	default:
		result = models.ComplianceResult{
			Description: criteria.Description,
			Status:      "NO ASSET",
			Response:    "Not Applicable",
			Impact:      0,
		}
	}

	return result
}
