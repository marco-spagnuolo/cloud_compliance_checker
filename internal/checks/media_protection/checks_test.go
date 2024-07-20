package media_protection

import (
	"testing"

	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
)

// TestCheckSystemMediaProtection tests CheckSystemMediaProtection
func TestCheckSystemMediaProtection(t *testing.T) {
	result := CheckSystemMediaProtection(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Protect system media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckCUIMediaAccess tests CheckCUIMediaAccess
func TestCheckCUIMediaAccess(t *testing.T) {
	result := CheckCUIMediaAccess(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Limit access to CUI on system media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckMediaSanitization tests CheckMediaSanitization
func TestCheckMediaSanitization(t *testing.T) {
	result := CheckMediaSanitization(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Sanitize or destroy system media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckMediaMarkings tests CheckMediaMarkings
func TestCheckMediaMarkings(t *testing.T) {
	result := CheckMediaMarkings(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Mark media with CUI markings",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckMediaAccessControl tests CheckMediaAccessControl
func TestCheckMediaAccessControl(t *testing.T) {
	result := CheckMediaAccessControl(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Control media access and accountability",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckCryptoMechanisms tests CheckCryptoMechanisms
func TestCheckCryptoMechanisms(t *testing.T) {
	result := CheckCryptoMechanisms(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Implement cryptographic mechanisms",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckRemovableMediaControl tests CheckRemovableMediaControl
func TestCheckRemovableMediaControl(t *testing.T) {
	result := CheckRemovableMediaControl(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Control removable media",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckPortableStorageDeviceProhibition tests CheckPortableStorageDeviceProhibition
func TestCheckPortableStorageDeviceProhibition(t *testing.T) {
	result := CheckPortableStorageDeviceProhibition(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Prohibit unauthorized portable storage devices",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckBackupCUIProtection tests CheckBackupCUIProtection
func TestCheckBackupCUIProtection(t *testing.T) {
	result := CheckBackupCUIProtection(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Protect backup CUI",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}
