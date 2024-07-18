package system

import (
	"cloud_compliance_checker/models"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go/service/ec2"
)

func CheckLogonAttempts(instance *ec2.Instance) models.ComplianceResult {
	success, err := checkPamConfiguration()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance limits unsuccessful logon attempts",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking PAM configuration: %v", err),
			Impact:      5,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance limits unsuccessful logon attempts",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance limits unsuccessful logon attempts",
			Status:      "FAIL",
			Response:    "PAM configuration does not limit logon attempts",
			Impact:      5,
		}
	}
}

func checkPamConfiguration() (bool, error) {
	cmd := exec.Command("grep", "pam_tally2", "/etc/pam.d/common-auth")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}

	if strings.Contains(string(output), "deny=") {
		return true, nil
	}

	return false, nil
}

func CheckPrivacyNotices(instance *ec2.Instance) models.ComplianceResult {
	filePath := "/etc/issue"
	exists, err := fileExists(filePath)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance provides privacy and security notices",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking privacy notice file: %v", err),
			Impact:      5,
		}
	}

	if exists {
		return models.ComplianceResult{
			Description: "Instance provides privacy and security notices",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance provides privacy and security notices",
			Status:      "FAIL",
			Response:    "Privacy notice file not found",
			Impact:      5,
		}
	}
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func CheckSessionLock(instance *ec2.Instance) models.ComplianceResult {
	// Verifica le configurazioni dello screensaver per il blocco della sessione
	success, err := checkScreenSaverConfiguration()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance uses session lock with pattern-hiding displays",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking screensaver configuration: %v", err),
			Impact:      5,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance uses session lock with pattern-hiding displays",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance uses session lock with pattern-hiding displays",
			Status:      "FAIL",
			Response:    "Session lock not properly configured",
			Impact:      5,
		}
	}
}

func checkScreenSaverConfiguration() (bool, error) {
	// Verifica se `gnome-screensaver` è installato e configurato correttamente
	cmd := exec.Command("gnome-screensaver-command", "--query")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 127 {
			// `gnome-screensaver-command` non trovato, verifica se `xscreensaver` è installato
			cmd = exec.Command("xscreensaver-command", "-time")
			output, err = cmd.Output()
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 127 {
					// Nessuno screensaver trovato
					return false, nil
				}
				return false, err
			}
		} else {
			return false, err
		}
	}

	// Placeholder logic per analizzare l'output dello screensaver
	if string(output) != "" {
		return true, nil
	}

	return false, nil
}

func CheckSessionTermination(instance *ec2.Instance) models.ComplianceResult {
	// Verifica le configurazioni del timeout della sessione
	success, err := checkSessionTimeoutConfiguration()
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance automatically terminates user sessions after a defined condition",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error checking session timeout configuration: %v", err),
			Impact:      5,
		}
	}

	if success {
		return models.ComplianceResult{
			Description: "Instance automatically terminates user sessions after a defined condition",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance automatically terminates user sessions after a defined condition",
			Status:      "FAIL",
			Response:    "Session timeout not properly configured",
			Impact:      5,
		}
	}
}

func checkSessionTimeoutConfiguration() (bool, error) {
	// Verifica se `TMOUT` è configurato correttamente nel file `/etc/profile`
	cmd := exec.Command("grep", "TMOUT", "/etc/profile")
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			// `grep` restituisce 1 se non trova nulla, che in questo caso significa che `TMOUT` non è configurato
			return false, nil
		}
		return false, err
	}

	// Placeholder logic per analizzare l'output
	if strings.Contains(string(output), "TMOUT") {
		return true, nil
	}

	return false, nil
}
