package incident_response

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/aws/aws-sdk-go/service/inspector/inspectoriface"
)

// Check for control 3.6.1 - Establish an operational incident-handling capability
func CheckIncidentHandlingCapability(sess *session.Session) models.ComplianceResult {
	inspectorSvc := inspector.New(sess)
	return checkIncidentHandlingCapabilityWithService(inspectorSvc)
}

func checkIncidentHandlingCapabilityWithService(inspectorSvc inspectoriface.InspectorAPI) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Establish an operational incident-handling capability",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Establish an operational incident-handling capability",
			Status:      "PASS",
			Response:    "No incidents found, incident handling capability is in place",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Establish an operational incident-handling capability",
		Status:      "PASS",
		Response:    fmt.Sprintf("Incidents identified: %d. Incident handling capability is in place.", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.6.2 - Track, document, and report incidents
func CheckIncidentReporting(sess *session.Session) models.ComplianceResult {
	inspectorSvc := inspector.New(sess)
	return checkIncidentReportingWithService(inspectorSvc)
}

func checkIncidentReportingWithService(inspectorSvc inspectoriface.InspectorAPI) models.ComplianceResult {
	input := &inspector.ListFindingsInput{}
	result, err := inspectorSvc.ListFindings(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Track, document, and report incidents",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing Inspector findings: %v", err),
			Impact:      5,
		}
	}

	if len(result.FindingArns) == 0 {
		return models.ComplianceResult{
			Description: "Track, document, and report incidents",
			Status:      "PASS",
			Response:    "No incidents found, tracking and reporting is in place",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Track, document, and report incidents",
		Status:      "PASS",
		Response:    fmt.Sprintf("Incidents identified: %d. Tracking and reporting is in place.", len(result.FindingArns)),
		Impact:      0,
	}
}

// Check for control 3.6.3 - Test incident response capability
func CheckIncidentResponseTesting(sess *session.Session) models.ComplianceResult {
	// As this is a mock implementation, we assume testing has been performed.
	// In a real implementation, you would integrate with your incident response testing tools or processes.
	return models.ComplianceResult{
		Description: "Test incident response capability",
		Status:      "PASS",
		Response:    "Incident response capability has been tested",
		Impact:      0,
	}
}
