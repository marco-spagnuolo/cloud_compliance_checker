package pers_security

import (
	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
)

// Check for control 3.9.1 - Screen individuals for CUI access
func CheckCUIScreening(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Screen individuals for CUI access",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.9.2 - Protect systems during personnel actions
func CheckPersonnelActionProtection(sess *session.Session) models.ComplianceResult {
	return models.ComplianceResult{
		Description: "Protect systems during personnel actions",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}
