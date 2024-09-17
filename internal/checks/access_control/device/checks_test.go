package device

import (
	"cloud_compliance_checker/models"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
)

func TestCheckMobileDeviceConnection(t *testing.T) {
	instance := &ec2.Instance{}
	result := CheckMobileDeviceConnection(instance, models.Criteria{})
	assert.Equal(t, "Instance controls connection of mobile devices", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckMobileDeviceEncryption(t *testing.T) {
	instance := &ec2.Instance{}
	result := CheckMobileDeviceEncryption(instance, models.Criteria{})
	assert.Equal(t, "Instance encrypts CUI on mobile devices", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckExternalSystemConnections(t *testing.T) {
	instance := &ec2.Instance{}
	result := CheckExternalSystemConnections(instance, models.Criteria{})
	assert.Equal(t, "Instance controls connections to external systems", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckPortableStorageUse(t *testing.T) {
	instance := &ec2.Instance{}
	result := CheckPortableStorageUse(instance, models.Criteria{})
	assert.Equal(t, "Instance limits use of portable storage devices on external systems", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckPublicCUIControl(t *testing.T) {
	instance := &ec2.Instance{}
	result := CheckPublicCUIControl(instance, models.Criteria{})
	assert.Equal(t, "Instance controls CUI on publicly accessible systems", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}
