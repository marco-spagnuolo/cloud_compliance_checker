package device

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/service/ec2"
)

// CheckMobileDeviceConnection checks if the instance controls connection of mobile devices.
func CheckMobileDeviceConnection(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	success, err := verifyMobileDeviceConnection()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance controls connection of mobile devices",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error verifying mobile device connection: %v", err),
			Impact:      criteria.Value,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance controls connection of mobile devices",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}
	return models.ComplianceResult{
		Description: "Instance controls connection of mobile devices",
		Status:      "FAIL",
		Response:    "Mobile device connection not properly controlled",
		Impact:      criteria.Value,
	}
}

func verifyMobileDeviceConnection() (bool, error) {
	// Simulate a controlled mobile device connection
	return true, nil
}

// CheckMobileDeviceEncryption checks if the instance encrypts CUI on mobile devices.
func CheckMobileDeviceEncryption(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	success, err := verifyMobileDeviceEncryption()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance encrypts CUI on mobile devices",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error verifying mobile device encryption: %v", err),
			Impact:      criteria.Value,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance encrypts CUI on mobile devices",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}
	return models.ComplianceResult{
		Description: "Instance encrypts CUI on mobile devices",
		Status:      "FAIL",
		Response:    "Mobile device encryption not properly implemented",
		Impact:      criteria.Value,
	}
}

func verifyMobileDeviceEncryption() (bool, error) {
	// Simulate encryption on mobile devices
	return true, nil
}

// CheckExternalSystemConnections checks if the instance controls connections to external systems.
func CheckExternalSystemConnections(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	success, err := verifyExternalSystemConnections()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance controls connections to external systems",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error verifying external system connections: %v", err),
			Impact:      criteria.Value,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance controls connections to external systems",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}
	return models.ComplianceResult{
		Description: "Instance controls connections to external systems",
		Status:      "FAIL",
		Response:    "External system connections not properly controlled",
		Impact:      criteria.Value,
	}
}

func verifyExternalSystemConnections() (bool, error) {
	// Simulate controlled connections to external systems
	return true, nil
}

// CheckPortableStorageUse checks if the instance limits the use of portable storage devices on external systems.
func CheckPortableStorageUse(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	success, err := verifyPortableStorageUse()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance limits use of portable storage devices on external systems",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error verifying portable storage use: %v", err),
			Impact:      criteria.Value,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance limits use of portable storage devices on external systems",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}
	return models.ComplianceResult{
		Description: "Instance limits use of portable storage devices on external systems",
		Status:      "FAIL",
		Response:    "Portable storage use not properly limited",
		Impact:      criteria.Value,
	}
}

func verifyPortableStorageUse() (bool, error) {
	// Simulate limited use of portable storage devices
	return true, nil
}

// CheckPublicCUIControl checks if the instance controls CUI on publicly accessible systems.
func CheckPublicCUIControl(instance *ec2.Instance, criteria models.Criteria) models.ComplianceResult {
	success, err := verifyPublicCUIControl()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance controls CUI on publicly accessible systems",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error verifying public CUI control: %v", err),
			Impact:      criteria.Value,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance controls CUI on publicly accessible systems",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}
	return models.ComplianceResult{
		Description: "Instance controls CUI on publicly accessible systems",
		Status:      "FAIL",
		Response:    "Public CUI control not properly implemented",
		Impact:      criteria.Value,
	}
}

func verifyPublicCUIControl() (bool, error) {
	// Simulate control of CUI on publicly accessible systems
	return true, nil
}
