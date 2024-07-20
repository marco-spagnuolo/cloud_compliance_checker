package integrity

// import (
// 	"testing"

// 	"cloud_compliance_checker/mocks"
// 	"cloud_compliance_checker/models"

// 	"github.com/aws/aws-sdk-go/aws/session"
// 	"github.com/aws/aws-sdk-go/service/inspector"
// 	"github.com/aws/aws-sdk-go/service/securityhub"
// 	"github.com/golang/mock/gomock"
// 	"github.com/stretchr/testify/assert"
// )

// func TestCheckSystemFlawCorrection(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockInspector := mocks.NewMockInspectorAPI(ctrl)
// 	mockInspector.EXPECT().ListFindings(gomock.Any()).Return(&inspector.ListFindingsOutput{
// 		FindingArns: []*string{},
// 	}, nil)

// 	result := checkSystemFlawCorrectionWithService(mockInspector)
// 	expected := models.ComplianceResult{
// 		Description: "Identify and correct system flaws",
// 		Status:      "PASS",
// 		Response:    "No system flaws found",
// 		Impact:      0,
// 	}

// 	assert.Equal(t, expected, result)
// }

// func TestCheckMaliciousCodeProtection(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockInspector := mocks.NewMockInspectorAPI(ctrl)
// 	mockInspector.EXPECT().ListFindings(gomock.Any()).Return(&inspector.ListFindingsOutput{
// 		FindingArns: []*string{},
// 	}, nil)

// 	result := checkMaliciousCodeProtectionWithService(mockInspector)
// 	expected := models.ComplianceResult{
// 		Description: "Provide protection from malicious code",
// 		Status:      "PASS",
// 		Response:    "No malicious code found",
// 		Impact:      0,
// 	}

// 	assert.Equal(t, expected, result)
// }

// func TestCheckSecurityAlertMonitoring(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockSecurityHub := mocks.NewMockSecurityHubAPI(ctrl)
// 	mockSecurityHub.EXPECT().GetFindings(gomock.Any()).Return(&securityhub.GetFindingsOutput{
// 		Findings: []*securityhub.AwsSecurityFinding{},
// 	}, nil)

// 	result := checkSecurityAlertMonitoringWithService(mockSecurityHub)
// 	expected := models.ComplianceResult{
// 		Description: "Monitor system security alerts",
// 		Status:      "PASS",
// 		Response:    "No security alerts found",
// 		Impact:      0,
// 	}

// 	assert.Equal(t, expected, result)
// }

// func TestCheckMaliciousCodeUpdates(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockInspector := mocks.NewMockInspectorAPI(ctrl)
// 	mockInspector.EXPECT().ListFindings(gomock.Any()).Return(&inspector.ListFindingsOutput{
// 		FindingArns: []*string{},
// 	}, nil)

// 	result := checkMaliciousCodeUpdatesWithService(mockInspector)
// 	expected := models.ComplianceResult{
// 		Description: "Update malicious code protection mechanisms",
// 		Status:      "PASS",
// 		Response:    "No updates needed for malicious code protection mechanisms",
// 		Impact:      0,
// 	}

// 	assert.Equal(t, expected, result)
// }

// func TestCheckSystemScans(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockInspector := mocks.NewMockInspectorAPI(ctrl)
// 	mockInspector.EXPECT().ListFindings(gomock.Any()).Return(&inspector.ListFindingsOutput{
// 		FindingArns: []*string{},
// 	}, nil)

// 	result := checkSystemScansWithService(mockInspector)
// 	expected := models.ComplianceResult{
// 		Description: "Perform periodic and real-time scans",
// 		Status:      "PASS",
// 		Response:    "No issues found during periodic and real-time scans",
// 		Impact:      0,
// 	}

// 	assert.Equal(t, expected, result)
// }

// func TestCheckCommunicationTrafficMonitoring(t *testing.T) {
// 	result := CheckCommunicationTrafficMonitoring(&session.Session{})
// 	expected := models.ComplianceResult{
// 		Description: "Monitor inbound and outbound communications",
// 		Status:      "Not Applicable",
// 		Response:    "This control is not applicable.",
// 		Impact:      0,
// 	}

// 	assert.Equal(t, expected, result)
// }

// func TestCheckUnauthorizedUseIdentification(t *testing.T) {
// 	result := CheckUnauthorizedUseIdentification(&session.Session{})
// 	expected := models.ComplianceResult{
// 		Description: "Identify unauthorized use of organizational systems",
// 		Status:      "Not Applicable",
// 		Response:    "This control is not applicable.",
// 		Impact:      0,
// 	}

// 	assert.Equal(t, expected, result)
// }
