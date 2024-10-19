package evaluation

import (
	"cloud_compliance_checker/config"
	"cloud_compliance_checker/discovery"
	iampolicy "cloud_compliance_checker/internal/checks/access_control"
	"cloud_compliance_checker/internal/checks/audit_and_accountability"
	"cloud_compliance_checker/internal/checks/config_management"
	"cloud_compliance_checker/internal/checks/id_auth"
	"cloud_compliance_checker/internal/checks/inc"
	"cloud_compliance_checker/internal/checks/integrity"
	"cloud_compliance_checker/internal/checks/maintenance"
	"cloud_compliance_checker/internal/checks/protection"
	"cloud_compliance_checker/internal/checks/risk_assesment"
	"cloud_compliance_checker/internal/checks/security_assesment"
	"cloud_compliance_checker/internal/checks/system_services_acquisition"
	"cloud_compliance_checker/models"
	"fmt"
	"time"

	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/jung-kurt/gofpdf"
	"github.com/pdfcpu/pdfcpu/pkg/api"
)

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
	//Controls:

	//03.01: Access Control

	//03.01.01 Account Management
	case "CheckUsersPolicies":
		err := iampolicy.RunCheckPolicies(cfg)
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
	//03.01.02 Access Enforcement
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
	// 03.01.03 Information Flow Enforcement
	case "CheckCUIFlow":
		err := check.RunCheckCUIFlow(cfg)
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
	// 03.01.04 Separation of Duties
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
	// 03.01.05 Least Privilege
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
	// 03.01.06 Least Privilege Privileged Accounts
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
	// 03.01.07 Least Privilege Privileged Functions
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
	// 03.01.08 Limit Unsuccessful Logon Attempts
	case "CheckLogonAttempts":
		err := check.RunLoginAttemptCheck(false)
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
	//03.01.10 Device Lock
	case "CheckSessionLock":
		err := iampolicy.RunSessionTimeoutCheck(cfg)
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
	// 03.01.11 Session Termination
	case "CheckSessionTermination":
		err := iampolicy.RunInactivitySessionCheck(cfg, "marco_admin")
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
	// 03.01.12 Remote Access Control
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
	// 03.01.20 Use of External Systems
	case "CheckExternalSystemConnections":
		err := iampolicy.RunRemoteMonitoringCheck(cfg)
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
	// Awareness and Training
	// 03.03.01 Event Logging
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
	// 03.03.02 Audit Record Content
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
	// 03.03.03 Audit Record Generation
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
	// 03.03.04 Audit Logging Failure
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
	// 03.03.05 Audit Record Review, Analysis, and Reporting
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
	// 03.03.06 Audit Record Reduction and Report Generation
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
	// 03.03.08 Protection of Audit Information
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
	// Configuration Management
	// 03.04.01 Baseline Configuration
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
	// 03.04.06 Least Functionality
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
	// 03.04.08 Configuration Change Control
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
	// 03.04.10 System Component Inventory
	// 03.04.11 Information Location
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
	// 03.04.12 System and Component Configuration for High-Risk Areas
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
	// 03.05.01 User identification and Authentication
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
		// Identification and Authentication

	// 03.05.02 Device Identification and Authentication
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
	// 03.05.03 Multi-Factor Authentication
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
	// 03.05.04 Replay-Resistant Authentication
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
	// 03.05.05 Multi-Factor Authentication
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
	// 03.05.04 Replay-Resistant Authentication
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

	case "CheckIRHandling":

		err := inc.RunCheckIR(cfg)
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

	case "CheckIRHandlingAndStore":

		err := inc.RunCheckIR(cfg)
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

	case "CheckIRTesting":

		err := inc.RunCheckIR(cfg)
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

	//Maintenance
	//03.07.04 Maintenance Tools
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
	// 03.07.05 Non-Local Maintenance
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
	// 03.07.06 Maintenance Personnel
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
	// Risk Assessment
	// 03.11.01 Risk Assessment
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
	// 03.11.02 Vulnerability Monitoring and Scanning
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
	// 03.11.04 Risk Renponse
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
	// Security Assessment
	// 03.12.01 Security Assessments
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
	// 03.12.03 Continuous Monitoring
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
	// 03.12.05 Information Exchange
	case "CheckIE":

		err := security_assesment.CheckExchangeAgreements(cfg)
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

	// System and Communications Protection
	// 03.13.01 Boundary Protection
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
	//03.13.04 Information in Shared System Resources
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
	// 03.13.05 Deny by Default
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
	// 03.13.08 Transmission and Storage Confidentiality
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
	// 03.13.09 Network Disconnect
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
	// 03.13.10 Cryptographic Key Establishment and Management
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
	// Cryptographic Protection
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
	// 03.13.12 Collaborative Computing Devices and Applications
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
	// 03.13.13 Mobile Code
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
	// 03.13.15 Session Authenticity
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
	// System and Information Integrity
	// 03.14.01 Flaw Remediation
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
	// 03.14.02 Malicious Code Protection
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
	// 03.14.03 Security Alerts
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
	// 03.14.06 Security Monitoring
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
	//03.14.08 Information Management and Reterntion
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

// EvaluateAssets evaluates all assets and returns the compliance results
func EvaluateAssets(controls models.NISTControls, cfg aws.Config) int {
	fmt.Println("=========================================")

	// Separator for readability
	fmt.Println("===== Compliance Evaluation Results =====")

	// Variabili per contare i controlli
	var compliantCount, nonCompliantCount, notApplicableCount, toBeImplementedCount int

	// Variabile per il punteggio
	score := 110

	// Genera il PDF con i dettagli dei controlli e aggiorna i contatori
	detailPDF := "detail_report.pdf"
	score = createDetailPDF(controls, cfg, detailPDF, &compliantCount, &nonCompliantCount, &notApplicableCount, &toBeImplementedCount)

	// Ora che i conteggi sono stati aggiornati, genera il PDF del riepilogo
	summaryPDF := "summary_report.pdf"
	CreateSummaryPDF(summaryPDF, score, compliantCount, nonCompliantCount, notApplicableCount, toBeImplementedCount, len(controls.Controls))

	// Controlla se i file PDF esistono e sono stati creati correttamente
	if _, err := os.Stat(summaryPDF); os.IsNotExist(err) {
		fmt.Println("Error: Summary PDF was not created.")
		return 0
	}

	if _, err := os.Stat(detailPDF); os.IsNotExist(err) {
		fmt.Println("Error: Detail PDF was not created.")
		return 0
	}

	// Concatena i due PDF
	finalPDF := "compliance_report.pdf"
	err := mergePDFs(summaryPDF, detailPDF, finalPDF)
	if err != nil {
		fmt.Printf("Error merging PDF: %v\n", err)
		return 0
	}

	return score
}

// CreateSummaryPDF genera un PDF con il titolo e il riepilogo
func CreateSummaryPDF(fileName string, score, compliantCount, nonCompliantCount, notApplicableCount, toBeImplementedCount, totalControls int) {
	// Inizializza il PDF
	pdf := gofpdf.New("P", "mm", "A4", "")

	// Aggiungi una pagina
	pdf.AddPage()

	// Imposta il titolo
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "NIST-800-171 v3 Compliance")
	pdf.Ln(12)

	// Aggiungi il punteggio totale, riepilogo e numero di controlli
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(40, 10, "Compliance Summary Report")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Total Score: %d", score))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Number of Controls: %d", totalControls))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Compliant Checks: %d", compliantCount))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Non-Compliant Checks: %d", nonCompliantCount))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Not Applicable Checks: %d", notApplicableCount))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total To Be Implemented Checks: %d", toBeImplementedCount))
	pdf.Ln(12)

	// Salva il PDF
	err := pdf.OutputFileAndClose(fileName)
	if err != nil {
		fmt.Printf("Error creating summary PDF: %v\n", err)
	}
}

// createDetailPDF genera un PDF con i dettagli dei controlli
func createDetailPDF(controls models.NISTControls, cfg aws.Config, fileName string, compliantCount, nonCompliantCount, notApplicableCount, toBeImplementedCount *int) int {
	// Inizializza il PDF
	pdf := gofpdf.New("P", "mm", "A4", "")

	// Aggiungi una pagina
	pdf.AddPage()

	// Variabile per il punteggio
	score := checkInstance(controls, cfg, pdf, compliantCount, nonCompliantCount, notApplicableCount, toBeImplementedCount)

	// Salva il PDF
	err := pdf.OutputFileAndClose(fileName)
	if err != nil {
		fmt.Printf("Error creating detail PDF: %v\n", err)
	}

	return score
}

// CheckInstance runs all compliance checks on the given instance (SINGLE INSTANCE) and returns the total score
func checkInstance(controls models.NISTControls, cfg aws.Config, pdf *gofpdf.Fpdf, compliantCount, nonCompliantCount, notApplicableCount, toBeImplementedCount *int) int {
	score := 110
	controlsPerPage := 4
	controlCount := 0

	for _, control := range controls.Controls {
		fmt.Printf("\n")
		fmt.Printf("\n*Control: %s - %s\n", control.ID, control.Name)
		fmt.Printf("\n")

		// Aggiungi i controlli nel PDF
		pdf.SetFont("Arial", "B", 14)
		pdf.MultiCell(0, 10, fmt.Sprintf("Control: %s - %s", control.ID, control.Name), "", "L", false)

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
			case "TO BE IMPLEMENTED":
				*toBeImplementedCount++
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

func mergePDFs(summaryReport, detailReport, outputFile string) error {
	// Lista dei file PDF da unire
	pdfFiles := []string{summaryReport, detailReport}

	// Aprire il file di output
	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer output.Close()

	// Unire i file PDF utilizzando pdfcpu
	if err := api.Merge("", pdfFiles, output, nil, false); err != nil {
		return fmt.Errorf("failed to merge PDFs: %v", err)
	}

	fmt.Printf("PDFs merged successfully into %s\n", outputFile)
	return nil
}
