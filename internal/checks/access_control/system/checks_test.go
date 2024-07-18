package system

import (
	"cloud_compliance_checker/models"
	"os"
	"os/exec"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
)

// Mocking exec.Command
var execCommand = exec.Command

func mockExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	switch args[3] {
	case "grep":
		// Simulate failure conditions
		if len(args) > 4 && args[4] == "pam_tally2" {
			os.Exit(1) // No matching pam_tally2 configuration
		} else if len(args) > 4 && args[4] == "TMOUT" {
			os.Exit(1) // No matching TMOUT configuration
		} else {
			os.Exit(1)
		}
	case "gnome-screensaver-command":
		os.Exit(127) // Command not found
	case "xscreensaver-command":
		os.Exit(127) // Command not found
	}
	os.Exit(1)
}

func TestCheckLogonAttempts(t *testing.T) {
	instance := &ec2.Instance{}
	expected := models.ComplianceResult{
		Description: "Instance limits unsuccessful logon attempts",
		Status:      "FAIL",
		Response:    "PAM configuration does not limit logon attempts",
		Impact:      5,
	}

	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()

	result := CheckLogonAttempts(instance)
	assert.Equal(t, expected, result)
}

func TestCheckPrivacyNotices(t *testing.T) {
	instance := &ec2.Instance{}
	filePath := "/etc/issue"

	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()

	expected := models.ComplianceResult{
		Description: "Instance provides privacy and security notices",
		Status:      "PASS",
		Response:    "Implemented",
		Impact:      5,
	}

	// Ensure the file does not exist to simulate failure
	os.Remove(filePath)

	result := CheckPrivacyNotices(instance)
	assert.Equal(t, expected, result)
}

func TestCheckSessionLockFail(t *testing.T) {
	instance := &ec2.Instance{}

	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()

	expected := models.ComplianceResult{
		Description: "Instance uses session lock with pattern-hiding displays",
		Status:      "FAIL",
		Response:    "Error checking screensaver configuration: exec: \"gnome-screensaver-command\": executable file not found in $PATH",
		Impact:      5,
	}

	result := CheckSessionLock(instance)
	assert.Equal(t, expected, result)
}

func TestCheckSessionTerminationFail(t *testing.T) {
	instance := &ec2.Instance{}

	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()

	expected := models.ComplianceResult{
		Description: "Instance automatically terminates user sessions after a defined condition",
		Status:      "FAIL",
		Response:    "Error checking screensaver configuration: exec: \"gnome-screensaver-command\": executable file not found in $PATH",
		Impact:      5,
	}

	result := CheckSessionTermination(instance)
	assert.Equal(t, expected, result)
}

//TODO add more test , this test fails on macos , test on linux on github actions
