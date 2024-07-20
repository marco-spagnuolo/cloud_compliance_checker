package physical_protection

import (
	"testing"

	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
)

// TestCheckPhysicalAccessLimitation tests CheckPhysicalAccessLimitation
func TestCheckPhysicalAccessLimitation(t *testing.T) {
	result := CheckPhysicalAccessLimitation(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Limit physical access to systems",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckPhysicalFacilityProtection tests CheckPhysicalFacilityProtection
func TestCheckPhysicalFacilityProtection(t *testing.T) {
	result := CheckPhysicalFacilityProtection(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Protect and monitor physical facility",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckVisitorMonitoring tests CheckVisitorMonitoring
func TestCheckVisitorMonitoring(t *testing.T) {
	result := CheckVisitorMonitoring(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Escort visitors and monitor activity",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckPhysicalAccessAuditLogs tests CheckPhysicalAccessAuditLogs
func TestCheckPhysicalAccessAuditLogs(t *testing.T) {
	result := CheckPhysicalAccessAuditLogs(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Maintain audit logs of physical access",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckPhysicalAccessDevices tests CheckPhysicalAccessDevices
func TestCheckPhysicalAccessDevices(t *testing.T) {
	result := CheckPhysicalAccessDevices(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Control and manage physical access devices",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckAlternateWorkSiteSafeguarding tests CheckAlternateWorkSiteSafeguarding
func TestCheckAlternateWorkSiteSafeguarding(t *testing.T) {
	result := CheckAlternateWorkSiteSafeguarding(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Safeguard CUI at alternate work sites",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}
