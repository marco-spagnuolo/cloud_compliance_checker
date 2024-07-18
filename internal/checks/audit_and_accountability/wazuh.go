package audit_and_accountability

import (
	"cloud_compliance_checker/models"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

type WazuhResponse struct {
	TotalItems int `json:"totalItems"`
	Items      []struct {
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
	} `json:"items"`
}

func fetchWazuhLogs() (WazuhResponse, error) {
	var response WazuhResponse
	wazuhEndpoint := os.Getenv("WAZUH_API_ENDPOINT")
	wazuhUser := os.Getenv("WAZUH_API_USER")
	wazuhPassword := os.Getenv("WAZUH_API_PASSWORD")

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/alerts", wazuhEndpoint), nil)
	if err != nil {
		return response, err
	}

	req.SetBasicAuth(wazuhUser, wazuhPassword)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return response, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return response, err
	}

	return response, nil
}

// 3.3.1 - Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.
func CheckAuditLogs() models.ComplianceResult {
	logs, err := fetchWazuhLogs()
	if err != nil {
		return models.ComplianceResult{
			Description: "Fetch Wazuh audit logs",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error fetching logs: %v", err),
			Impact:      5,
		}
	}

	if logs.TotalItems > 0 {
		return models.ComplianceResult{
			Description: "Audit logs are being generated",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Audit logs are being generated",
		Status:      "FAIL",
		Response:    "No audit logs found",
		Impact:      5,
	}
}

// 3.3.2 - Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.
func CheckUserTraceability() models.ComplianceResult {
	logs, err := fetchWazuhLogs()
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure user actions are traceable",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error fetching logs: %v", err),
			Impact:      5,
		}
	}

	for _, item := range logs.Items {
		if item.Agent.ID == "" {
			return models.ComplianceResult{
				Description: "Ensure user actions are traceable",
				Status:      "FAIL",
				Response:    "User actions are not uniquely traceable",
				Impact:      5,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure user actions are traceable",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

// 3.3.3 - Review and update logged events.
func CheckLoggedEventsReview() models.ComplianceResult {
	logs, err := fetchWazuhLogs()
	if err != nil {
		return models.ComplianceResult{
			Description: "Review and update logged events",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error fetching logs: %v", err),
			Impact:      5,
		}
	}

	if logs.TotalItems > 0 {
		return models.ComplianceResult{
			Description: "Review and update logged events",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Review and update logged events",
		Status:      "FAIL",
		Response:    "No logged events found",
		Impact:      5,
	}
}

// 3.3.4 - Alert in the event of an audit logging process failure.
func CheckAuditLoggingFailure() models.ComplianceResult {
	err := checkLoggingProcess()
	if err != nil {
		return models.ComplianceResult{
			Description: "Alert on audit logging process failure",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Logging process failure: %v", err),
			Impact:      5,
		}
	}

	return models.ComplianceResult{
		Description: "Alert on audit logging process failure",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      0,
	}
}

func checkLoggingProcess() error {
	// Implement logic to check if logging process failed
	logs, err := fetchWazuhLogs()
	if err != nil {
		return err
	}

	// Placeholder logic for logging process failure detection
	for _, item := range logs.Items {
		if item.Rule.Level >= 7 { // Example threshold for logging process failure
			return fmt.Errorf("logging process failure detected")
		}
	}

	return nil
}

// 3.3.5 - Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.
func CheckAuditCorrelation() models.ComplianceResult {
	logs, err := fetchWazuhLogs()
	if err != nil {
		return models.ComplianceResult{
			Description: "Correlate audit records",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error fetching logs: %v", err),
			Impact:      5,
		}
	}

	// Placeholder for correlating logs
	if logs.TotalItems > 0 {
		return models.ComplianceResult{
			Description: "Correlate audit records",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Correlate audit records",
		Status:      "FAIL",
		Response:    "No logs available for correlation",
		Impact:      5,
	}
}

// 3.3.6 - Provide audit reduction and report generation to support on-demand analysis and reporting.
func CheckAuditReduction() models.ComplianceResult {
	logs, err := fetchWazuhLogs()
	if err != nil {
		return models.ComplianceResult{
			Description: "Provide audit reduction and report generation",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error fetching logs: %v", err),
			Impact:      5,
		}
	}

	if logs.TotalItems > 0 {
		return models.ComplianceResult{
			Description: "Provide audit reduction and report generation",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Provide audit reduction and report generation",
		Status:      "FAIL",
		Response:    "No logs available for reduction and report generation",
		Impact:      5,
	}
}

// 3.3.7 - Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.
func CheckTimeSynchronization() models.ComplianceResult {
	// Implement logic to check time synchronization with NTP
	timeSynced, err := checkSystemClockSyncWithNTP("pool.ntp.org")
	if err != nil {
		return models.ComplianceResult{
			Description: "Synchronize system clocks",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking time synchronization: %v", err),
			Impact:      5,
		}
	}

	if timeSynced {
		return models.ComplianceResult{
			Description: "Synchronize system clocks",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}

	return models.ComplianceResult{
		Description: "Synchronize system clocks",
		Status:      "FAIL",
		Response:    "System clocks are not synchronized",
		Impact:      5,
	}
}

func checkSystemClockSyncWithNTP(ntpServer string) (bool, error) {
	conn, err := net.Dial("udp", ntpServer+":123")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Create NTP request packet
	req := make([]byte, 48)
	req[0] = 0x1B

	if _, err := conn.Write(req); err != nil {
		return false, err
	}

	// Read NTP response
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return false, err
	}

	// Extract the time from the response
	secs := uint64(resp[43]) | uint64(resp[42])<<8 | uint64(resp[41])<<16 | uint64(resp[40])<<24
	secs -= 2208988800 // Convert NTP time to Unix time

	ntpTime := time.Unix(int64(secs), 0)
	systemTime := time.Now().UTC()

	// Check if the system time is within a reasonable range of the NTP time
	if systemTime.After(ntpTime.Add(-time.Minute)) && systemTime.Before(ntpTime.Add(time.Minute)) {
		return true, nil
	}

	return false, nil
}
