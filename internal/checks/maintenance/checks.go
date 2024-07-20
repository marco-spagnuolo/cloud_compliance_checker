package maintenance

import (
	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
)

// Check for control 3.7.1 - Perform system maintenance
func CheckSystemMaintenance(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Perform system maintenance",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.7.2 - Provide maintenance controls
func CheckMaintenanceControls(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Provide maintenance controls",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.7.3 - Sanitize equipment for off-site maintenance
func CheckOffsiteMaintenanceSanitization(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Sanitize equipment for off-site maintenance",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.7.4 - Check media for malicious code
func CheckDiagnosticMediaForMaliciousCode(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Check media for malicious code",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.7.5 - Require MFA for nonlocal maintenance
func CheckNonlocalMaintenanceMFA(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Require MFA for nonlocal maintenance",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.7.6 - Supervise maintenance activities
func CheckMaintenanceSupervision(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Supervise maintenance activities",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}
