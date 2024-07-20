package media_protection

import (
	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
)

// Check for control 3.8.1 - Protect system media
func CheckSystemMediaProtection(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Protect system media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.2 - Limit access to CUI on system media
func CheckCUIMediaAccess(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Limit access to CUI on system media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.3 - Sanitize or destroy system media
func CheckMediaSanitization(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Sanitize or destroy system media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.4 - Mark media with CUI markings
func CheckMediaMarkings(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Mark media with CUI markings",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.5 - Control media access and accountability
func CheckMediaAccessControl(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Control media access and accountability",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.6 - Implement cryptographic mechanisms
func CheckCryptoMechanisms(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Implement cryptographic mechanisms",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.7 - Control removable media
func CheckRemovableMediaControl(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Control removable media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.8 - Prohibit unauthorized portable storage devices
func CheckPortableStorageDeviceProhibition(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Prohibit unauthorized portable storage devices",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.8.9 - Protect backup CUI
func CheckBackupCUIProtection(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Protect backup CUI",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}
