package pers_security

import (
	"testing"

	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
)

// TestCheckCUIScreening tests CheckCUIScreening
func TestCheckCUIScreening(t *testing.T) {
	result := CheckCUIScreening(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Screen individuals for CUI access",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckPersonnelActionProtection tests CheckPersonnelActionProtection
func TestCheckPersonnelActionProtection(t *testing.T) {
	result := CheckPersonnelActionProtection(&session.Session{})
	expected := models.ComplianceResult{
		Description: "Protect systems during personnel actions",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}
