package evaluation

import (
	"cloud_compliance_checker/config"
	"cloud_compliance_checker/discovery"
	iampolicy "cloud_compliance_checker/internal/checks/access_control"
	"cloud_compliance_checker/internal/checks/audit_and_accountability"
	"cloud_compliance_checker/internal/checks/config_management"
	"cloud_compliance_checker/internal/checks/id_auth"
	"cloud_compliance_checker/internal/checks/integrity"
	"cloud_compliance_checker/internal/checks/maintenance"
	"cloud_compliance_checker/internal/checks/protection"
	"cloud_compliance_checker/internal/checks/risk_assesment"
	"cloud_compliance_checker/internal/checks/security_assesment"
	"cloud_compliance_checker/internal/checks/system_services_acquisition"
	"cloud_compliance_checker/models"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/jung-kurt/gofpdf"
)

// EvaluateAssets evaluates all assets and returns the compliance results
func EvaluateAssets(controls models.NISTControls, cfg aws.Config) int {
	fmt.Println("=========================================")

	// Separator for readability
	fmt.Println("===== Compliance Evaluation Results =====")

	// Inizializza il PDF
	pdf := gofpdf.New("P", "mm", "A4", "")

	// Aggiungi una pagina
	pdf.AddPage()

	// Imposta il titolo
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Compliance Evaluation Report")
	pdf.Ln(12)

	// Variabili per contare i controlli
	var compliantCount, nonCompliantCount, notApplicableCount int

	// Variabile per il punteggio
	score := checkInstance(controls, cfg, pdf, &compliantCount, &nonCompliantCount, &notApplicableCount)

	// Aggiungi il punteggio totale e il riepilogo alla prima pagina
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(40, 10, "Compliance Summary")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Total Score: %d", score))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Compliant Checks: %d", compliantCount))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Non-Compliant Checks: %d", nonCompliantCount))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Not Applicable Checks: %d", notApplicableCount))
	pdf.Ln(12)

	// Genera il PDF alla fine della valutazione
	err := pdf.OutputFileAndClose("compliance_report.pdf")
	if err != nil {
		fmt.Printf("Error creating PDF: %v\n", err)
	}

	return score
}

// CheckInstance runs all compliance checks on the given instance (SINGLE INSTANCE) and returns the total score
func checkInstance(controls models.NISTControls, cfg aws.Config, pdf *gofpdf.Fpdf, compliantCount, nonCompliantCount, notApplicableCount *int) int {
	score := 110
	controlsPerPage := 4
	controlCount := 0

	for _, control := range controls.Controls {
		fmt.Printf("\n")
		fmt.Printf("\n*Control: %s - %s\n", control.ID, control.Name)
		fmt.Printf("\n")

		// Aggiungi i controlli nel PDF
		pdf.SetFont("Arial", "B", 14)
		pdf.MultiCell(0, 10, fmt.Sprintf("Control: %s - %s", control.ID, control.Name), "", "L", false) // Usa 'Name'

		for _, criteria := range control.Criteria {
			result := evaluateCriteria(criteria, cfg)

			// Print results for each check in a readable format
			fmt.Printf("\n")
			fmt.Printf("  Check: %s\n", criteria.CheckFunction)
			fmt.Printf("    Description: %s\n", criteria.Description)
			fmt.Printf("    Result: %s\n", result.Status)
			fmt.Printf("    Impact: %d\n", criteria.Value)

			// Aggiungi i dettagli del criterio nel PDF
			pdf.SetFont("Arial", "", 12)
			pdf.MultiCell(0, 8, fmt.Sprintf("  Check: %s", criteria.CheckFunction), "", "L", false)
			pdf.MultiCell(0, 8, fmt.Sprintf("    Description: %s", criteria.Description), "", "L", false)
			pdf.MultiCell(0, 8, fmt.Sprintf("    Result: %s", result.Status), "", "L", false)
			pdf.MultiCell(0, 8, fmt.Sprintf("    Impact: %d", criteria.Value), "", "L", false)
			pdf.Ln(8)

			// Aggiorna i contatori in base allo stato del controllo
			switch result.Status {
			case "COMPLIANT":
				*compliantCount++
			case "NOT COMPLIANT":
				*nonCompliantCount++
			case "NOT APPLICABLE":
				*notApplicableCount++
			}

			// Controlla il numero di controlli per pagina
			controlCount++
			if controlCount >= controlsPerPage {
				// Aggiungi una nuova pagina e resetta il contatore
				pdf.AddPage()
				controlCount = 0
			}

			score -= result.Impact
		}
	}

	return score
}

// evaluateCriteria evaluates the criteria for a given instance and returns the compliance result
func evaluateCriteria(criteria models.Criteria,
	cfg aws.Config) models.ComplianceResult {
	var result models.ComplianceResult
	check := iampolicy.NewIAMCheck(cfg)

	switch criteria.CheckFunction {

	case "//": // Not applicable
		result = models.ComplianceResult{
			Status:   "NOT APPLICABLE",
			Response: "Check not applicable",
			Impact:   criteria.Value,
		}
		return result

	case "TBI": // To be implemented
		result = models.ComplianceResult{
			Status:   "TO BE IMPLEMENTED",
			Response: "Check to be implemented",
			Impact:   criteria.Value,
		}
		return result

	case "CheckUsersPolicies":
		err := check.RunCheckPolicies()
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
		}
	case "CheckAcceptedPolicies":
		err := check.RunCheckAcceptedPolicies()
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
	case "CheckCUIFlow":
		err := check.RunCheckCUIFlow()
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
	case "CheckSeparateDuties":
		err := check.RunCheckSeparateDuties()
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
	case "CheckLeastPrivilege":
		err := check.RunPrivilegeCheck()
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
	case "CheckPrivilegedAccounts":
		err := check.RunPrivilegeAccountCheck()
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
	case "CheckPreventPrivilegedFunctions":
		err := check.RunPrivilegedFunctionCheck()
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
	case "CheckLogonAttempts":
		// Carica gli utenti dal file di configurazione
		usersFromConfig, err := iampolicy.LoadUsersFromConfig()
		if err != nil {
			result = models.ComplianceResult{
				Description: "Errore nel caricamento degli utenti",
				Status:      "NOT COMPLIANT",
				Response:    err.Error(),
				Impact:      criteria.Value,
			}
			fmt.Printf("\n[ERROR]: %v\n", err)
			return result
		}

		// Cerca specificamente l'utente marco_admin
		user, ok := usersFromConfig["marco_admin"]
		if !ok {
			result = models.ComplianceResult{
				Description: "Utente marco_admin non trovato nella configurazione",
				Status:      "NOT COMPLIANT",
				Response:    "Impossibile eseguire il controllo senza l'utente marco_admin",
				Impact:      criteria.Value,
			}
			fmt.Printf("\n[ERROR]: %v\n", err)
			return result
		}

		// Carica la politica di accesso definita nel file di configurazione
		loginPolicy := config.AppConfig.AWS.LoginPolicy

		// Esegui il controllo del tentativo di accesso per marco_admin
		err = check.RunLoginAttemptCheck(user.Name, false, loginPolicy)
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
	case "CheckSessionLock":
		err := check.RunSessionTimeoutCheck(cfg)
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
	case "CheckSessionTermination":
		err := check.RunInactivitySessionCheck(cfg, "marco_admin")
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
	case "CheckRemoteAccessControl":
		remoteAccessCheck := iampolicy.NewRemoteAccessCheck(cfg)
		err := remoteAccessCheck.RunRemoteAccessCheck()
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
	case "CheckExternalSystemConnections":
		err := check.RunRemoteMonitoringCheck(cfg)
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
	case "CheckAuditLogs":
		aa := audit_and_accountability.NewEventLoggingCheck(cfg, []string{"AWS_EC2"}, time.Now(), 30)
		err := aa.RunEventLoggingCheck()
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
	case "CheckUserTraceability":
		aa := audit_and_accountability.NewAuditLogCheck(cfg, 0)
		err := aa.RunAuditLogCheck()
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
	case "CheckLoggedEventsRetention":
		aa := audit_and_accountability.NewAuditLogCheck(cfg, 90) // TODO - ask user
		err := aa.RunAuditLogCheck()
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
	case "CheckLoggingFailure":
		lfc := audit_and_accountability.NewLoggingFailureCheck(cfg, 24*time.Hour, nil, "mittente@example.com", "destinatario@example.com")
		err := lfc.RunLoggingFailureCheck()
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
	case "CheckAuditLogAnalysis":
		aa := audit_and_accountability.NewAuditLogAnalysis(cfg, []string{"failed", "unauthorized", "error"})
		logGroupName := "/aws/lambda/my-function"
		err := aa.RunAuditLogAnalysis(logGroupName)
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
			Response:    "Audit log analysis check passed",
			Impact:      0,
		}
	case "CheckAuditRecordReduction":
		aa := audit_and_accountability.NewAuditLogCheck(cfg, 30) // 30-day retention for this check
		err := aa.RunAuditLogCheck()
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

	case "CheckAuditSecurity":
		aa := audit_and_accountability.NewAuditProtectionCheck(cfg, "marco_admin")
		err := aa.RunAuditProtectionCheck()
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

	case "CheckBaselineConfigurations":
		err := config_management.RunAWSBaselineCheck(cfg, &config.AppConfig.AWS)

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
	case "CheckEssentialCapabilities":
		err := config_management.RunAWSResourceReview(cfg)

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

	case "CheckAuthorizedSoftware":
		err := config_management.RunSoftwareExecutionCheck(cfg)

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

	case "CheckInformationLocation":
		assets := discovery.DiscoverAssets(cfg)

		config_management.DocumentDiscoveredAssets(assets)
		err := config_management.DisplayCUIComponents()
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

	case "CheckHighRiskTravel":
		err := config_management.CheckHighRiskTravelCompliance(cfg)
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

	case "CheckUserIdentification":
		err := id_auth.RunComplianceCheck(cfg)
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
	case "CheckDeviceIdentification":
		err := id_auth.CheckMac(cfg)
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

	case "CheckMFA":
		// Create IAM client
		iamClient := iam.NewFromConfig(cfg)

		// Enforce MFA for users
		err := id_auth.EnforceMFAForUsers(iamClient)
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
	case "CheckRRA":
		iamClient := iam.NewFromConfig(cfg)

		err := id_auth.EnforceMFAForUsers(iamClient)
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

	case "CheckIAM":
		err := id_auth.CheckIAM(cfg)
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
	case "CheckPasswordComplexity":

		err := id_auth.CheckPasswordPolicyEnforcement(cfg)
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

	case "CheckMaintainanceTools":

		err := maintenance.RunMonitorCheck(cfg)
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
	case "CheckNonLocalMaintainance":

		err := maintenance.CheckNonLocalMaintenanceCompliance(cfg)
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
	case "CheckMaintainancePersonnel":

		err := maintenance.CheckMaintenanceAuthorization(cfg)
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

	case "CheckRA":

		err := risk_assesment.ScheduleRiskAssessment(cfg)
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
	case "CheckMonitorAndScanning":

		err := risk_assesment.CheckAndStartVulnerabilityScan(cfg)
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
	case "CheckRiskRensponse":

		err := risk_assesment.VerifyAutoRiskAssessment(cfg)
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
	case "CheckSA":

		err := security_assesment.CheckMonitoringTools(cfg)
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
	case "CheckCM":

		err := security_assesment.CheckMonitoringTools(cfg)
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

	case "CheckBP":

		err := protection.VerifyComponents(cfg)
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

	case "CheckTSC":

		err := protection.CheckTransmissionAndStorageConfidentiality(cfg)
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

	case "CheckNetworkDisconnect":
		err := protection.CheckSessionTimeouts(cfg)
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

	case "CheckCKEM":
		err := protection.CheckKeyManagement(cfg)
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

	case "CheckCP":

		err := protection.CheckS3Confidentiality(cfg)
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

	case "CheckCCDA":

		err := protection.CheckCollaborativeDeviceSettings(cfg)
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

	case "CheckMC":

		err := protection.CheckMobileCode(cfg)
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

	case "CheckSessionAuthenticity":

		err := protection.CheckSessionAuthenticity(cfg)
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

	case "CheckFlawRemediation":

		err := integrity.CheckSystemFlawRemediation(cfg)
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

	case "CheckMalwareProtection":

		err := integrity.CheckSystemFlawRemediation(cfg)
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

	case "CheckSecurityAlerts":

		err := integrity.CheckLambdaAndS3Notifications(cfg)
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
	case "CheckSystemMonitoring":

		err := integrity.CheckSystemMonitoring(cfg)
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

	case "CheckSEP":

		err := system_services_acquisition.CheckSecurityEngineeringPrinciples(cfg)
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

// generatePDFReport genera un report PDF con i risultati della valutazione di conformità
func GeneratePDFReport(results []models.ComplianceResult, score int) error {
	pdf := gofpdf.New("P", "mm", "A4", "")

	// Aggiungi una pagina
	pdf.AddPage()

	// Titolo del report
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Compliance Evaluation Report")
	pdf.Ln(12)

	// Punteggio totale
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Total Compliance Score: %d", score))
	pdf.Ln(10)

	// Aggiungi risultati
	for _, result := range results {
		pdf.Cell(40, 10, fmt.Sprintf("Check: %s - Status: %s - Impact: %d", result.Description, result.Status, result.Impact))
		pdf.Ln(8)
	}

	// Salva il file PDF
	err := pdf.OutputFileAndClose("compliance_report.pdf")
	if err != nil {
		return err
	}

	fmt.Println("Report PDF generato con successo: compliance_report.pdf")
	return nil
}
