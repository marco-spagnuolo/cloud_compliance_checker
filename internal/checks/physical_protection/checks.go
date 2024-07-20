package physical_protection

import (
	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
)

// Check for control 3.10.1 - Limit physical access to systems
func CheckPhysicalAccessLimitation(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Limit physical access to systems",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.10.2 - Protect and monitor physical facility
func CheckPhysicalFacilityProtection(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Protect and monitor physical facility",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.10.3 - Escort visitors and monitor activity
func CheckVisitorMonitoring(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Escort visitors and monitor activity",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.10.4 - Maintain audit logs of physical access
func CheckPhysicalAccessAuditLogs(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Maintain audit logs of physical access",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.10.5 - Control and manage physical access devices
func CheckPhysicalAccessDevices(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Control and manage physical access devices",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.10.6 - Safeguard CUI at alternate work sites
func CheckAlternateWorkSiteSafeguarding(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Safeguard CUI at alternate work sites",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}
