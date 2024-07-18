package audit_and_accountability

import (
	"cloud_compliance_checker/models"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockFetchWazuhLogs() (WazuhResponse, error) {
	return WazuhResponse{
		TotalItems: 1,
		Items: []struct {
			ID   string `json:"id"`
			Rule struct {
				Level   int    `json:"level"`
				ID      string `json:"id"`
				Freq    int    `json:"firedtimes"`
				Comment string `json:"comment"`
			} `json:"rule"`
			Agent struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"agent"`
			Manager struct {
				Name string `json:"name"`
			} `json:"manager"`
			Source struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			} `json:"srcip"`
			Location string `json:"location"`
			FullLog  string `json:"full_log"`
		}{
			{
				ID: "1",
				Rule: struct {
					Level   int    `json:"level"`
					ID      string `json:"id"`
					Freq    int    `json:"firedtimes"`
					Comment string `json:"comment"`
				}{
					Level:   5,
					ID:      "1001",
					Freq:    1,
					Comment: "Test comment",
				},
				Agent: struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}{
					ID:   "001",
					Name: "TestAgent",
				},
				Manager: struct {
					Name string `json:"name"`
				}{
					Name: "TestManager",
				},
				Source: struct {
					IP   string `json:"ip"`
					Port int    `json:"port"`
				}{
					IP:   "192.168.1.1",
					Port: 8080,
				},
				Location: "TestLocation",
				FullLog:  "This is a full log",
			},
		},
	}, nil
}

func mockCheckSystemClockSyncWithNTP(ntpServer string) (bool, error) {
	// Simulate that the system clock is synchronized with the NTP server
	if ntpServer == "pool.ntp.org" {
		return true, nil
	}
	return false, fmt.Errorf("unable to reach NTP server")
}

func TestCheckAuditLogs(t *testing.T) {
	audit := &AuditAndAccountability{
		FetchWazuhLogs: mockFetchWazuhLogs,
	}
	expected := models.ComplianceResult{
		Description: "Audit logs are being generated",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}

	result := audit.CheckAuditLogs()
	assert.Equal(t, expected, result)
}

func TestCheckUserTraceability(t *testing.T) {
	audit := &AuditAndAccountability{
		FetchWazuhLogs: mockFetchWazuhLogs,
	}
	expected := models.ComplianceResult{
		Description: "Ensure user actions are traceable",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}

	result := audit.CheckUserTraceability()
	assert.Equal(t, expected, result)
}

func TestCheckLoggedEventsReview(t *testing.T) {
	audit := &AuditAndAccountability{
		FetchWazuhLogs: mockFetchWazuhLogs,
	}
	expected := models.ComplianceResult{
		Description: "Review and update logged events",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}

	result := audit.CheckLoggedEventsReview()
	assert.Equal(t, expected, result)
}

func TestCheckAuditLoggingFailure(t *testing.T) {
	audit := &AuditAndAccountability{
		FetchWazuhLogs: mockFetchWazuhLogs,
	}
	expected := models.ComplianceResult{
		Description: "Alert on audit logging process failure",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}

	result := audit.CheckAuditLoggingFailure()
	assert.Equal(t, expected, result)
}

func TestCheckAuditCorrelation(t *testing.T) {
	audit := &AuditAndAccountability{
		FetchWazuhLogs: mockFetchWazuhLogs,
	}
	expected := models.ComplianceResult{
		Description: "Correlate audit records",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}

	result := audit.CheckAuditCorrelation()
	assert.Equal(t, expected, result)
}

func TestCheckAuditReduction(t *testing.T) {
	audit := &AuditAndAccountability{
		FetchWazuhLogs: mockFetchWazuhLogs,
	}
	expected := models.ComplianceResult{
		Description: "Provide audit reduction and report generation",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}

	result := audit.CheckAuditReduction()
	assert.Equal(t, expected, result)
}

func TestCheckTimeSynchronization(t *testing.T) {
	audit := &AuditAndAccountability{
		CheckSystemClockSyncWithNTP: mockCheckSystemClockSyncWithNTP,
	}
	expected := models.ComplianceResult{
		Description: "Synchronize system clocks",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}

	result := audit.CheckTimeSynchronization()
	assert.Equal(t, expected, result)
}
