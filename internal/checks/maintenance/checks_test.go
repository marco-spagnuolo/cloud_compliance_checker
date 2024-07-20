package maintenance

import (
	"testing"

	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
)

// TestCheckSystemMaintenance tests CheckSystemMaintenance
func TestCheckSystemMaintenance(t *testing.T) {
	result := CheckSystemMaintenance(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Perform system maintenance",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckMaintenanceControls tests CheckMaintenanceControls
func TestCheckMaintenanceControls(t *testing.T) {
	result := CheckMaintenanceControls(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Provide maintenance controls",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckOffsiteMaintenanceSanitization tests CheckOffsiteMaintenanceSanitization
func TestCheckOffsiteMaintenanceSanitization(t *testing.T) {
	result := CheckOffsiteMaintenanceSanitization(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Sanitize equipment for off-site maintenance",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckDiagnosticMediaForMaliciousCode tests CheckDiagnosticMediaForMaliciousCode
func TestCheckDiagnosticMediaForMaliciousCode(t *testing.T) {
	result := CheckDiagnosticMediaForMaliciousCode(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Check media for malicious code",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckNonlocalMaintenanceMFA tests CheckNonlocalMaintenanceMFA
func TestCheckNonlocalMaintenanceMFA(t *testing.T) {
	result := CheckNonlocalMaintenanceMFA(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Require MFA for nonlocal maintenance",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckMaintenanceSupervision tests CheckMaintenanceSupervision
func TestCheckMaintenanceSupervision(t *testing.T) {
	result := CheckMaintenanceSupervision(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Supervise maintenance activities",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}
