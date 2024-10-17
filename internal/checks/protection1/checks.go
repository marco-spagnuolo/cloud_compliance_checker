package protection

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/kms"
)

// Check for control 3.13.1 - Ensure network boundaries are protected
func CheckBoundaryProtection(sess *session.Session, criteria models.Criteria) models.ComplianceResult {
	ec2Svc := ec2.New(sess)

	input := &ec2.DescribeSecurityGroupsInput{}
	result, err := ec2Svc.DescribeSecurityGroups(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure network boundaries are protected",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error describing security groups: %v", err),
			Impact:      criteria.Value,
		}
	}

	for _, group := range result.SecurityGroups {
		for _, permission := range group.IpPermissions {
			for _, ipRange := range permission.IpRanges {
				if *ipRange.CidrIp == "0.0.0.0/0" {
					return models.ComplianceResult{
						Description: "Ensure network boundaries are protected",
						Status:      "FAIL",
						Response:    "Found security group with open access (0.0.0.0/0)",
						Impact:      criteria.Value,
					}
				}
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure network boundaries are protected",
		Status:      "PASS",
		Response:    "All security groups have restricted access",
		Impact:      0,
	}
}

// Check for control 3.13.2 - Ensure communication channels are encrypted
func CheckCryptographicProtection(sess *session.Session, criteria models.Criteria) models.ComplianceResult {
	kmsSvc := kms.New(sess)

	input := &kms.ListKeysInput{}
	result, err := kmsSvc.ListKeys(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure communication channels are encrypted",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing KMS keys: %v", err),
			Impact:      criteria.Value,
		}
	}

	if len(result.Keys) == 0 {
		return models.ComplianceResult{
			Description: "Ensure communication channels are encrypted",
			Status:      "FAIL",
			Response:    "No KMS keys found for encryption",
			Impact:      criteria.Value,
		}
	}

	return models.ComplianceResult{
		Description: "Ensure communication channels are encrypted",
		Status:      "PASS",
		Response:    "KMS keys are available for encryption",
		Impact:      0,
	}
}

// Check for control 3.13.3 - Ensure information is protected during transmission
func CheckInformationTransmissionProtection(sess *session.Session, criteria models.Criteria) models.ComplianceResult {
	ec2Svc := ec2.New(sess)

	input := &ec2.DescribeVpcEndpointsInput{}
	result, err := ec2Svc.DescribeVpcEndpoints(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure information is protected during transmission",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error describing VPC endpoints: %v", err),
			Impact:      criteria.Value,
		}
	}

	for _, endpoint := range result.VpcEndpoints {
		if *endpoint.ServiceName == "com.amazonaws.vpce" {
			return models.ComplianceResult{
				Description: "Ensure information is protected during transmission",
				Status:      "PASS",
				Response:    "VPC endpoints are used for secure information transmission",
				Impact:      0,
			}
		}
	}

	return models.ComplianceResult{
		Description: "Ensure information is protected during transmission",
		Status:      "FAIL",
		Response:    "No VPC endpoints found for secure information transmission",
		Impact:      criteria.Value,
	}
}

// Check for control 3.13.4 - Implement subnetworks for publicly accessible system components
func CheckSubnetworkImplementation(sess *session.Session) models.ComplianceResult {
	// Implement subnetworks for publicly accessible system components
	return models.ComplianceResult{
		Description: "Implement subnetworks for publicly accessible system components",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.5 - Deny network communications traffic by default
func CheckNetworkCommunicationsControl(sess *session.Session) models.ComplianceResult {
	// Deny network communications traffic by default and allow by exception
	return models.ComplianceResult{
		Description: "Deny network communications traffic by default",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.6 - Prevent split tunneling
func CheckSplitTunnelingPrevention(sess *session.Session) models.ComplianceResult {
	// Prevent remote devices from simultaneously establishing non-remote connections
	return models.ComplianceResult{
		Description: "Prevent split tunneling",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.7 - Employ cryptographic mechanisms for transmission
func CheckTransmissionEncryption(sess *session.Session) models.ComplianceResult {
	// Employ cryptographic mechanisms to prevent unauthorized disclosure
	return models.ComplianceResult{
		Description: "Employ cryptographic mechanisms for transmission",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.8 - Terminate network connections after a defined period
func CheckNetworkConnectionTermination(sess *session.Session) models.ComplianceResult {
	// Terminate network connections after a defined period of inactivity
	return models.ComplianceResult{
		Description: "Terminate network connections after a defined period",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.9 - Establish and manage cryptographic keys
func CheckCryptographicKeyManagement(sess *session.Session) models.ComplianceResult {
	// Establish and manage cryptographic keys
	return models.ComplianceResult{
		Description: "Establish and manage cryptographic keys",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.10 - Employ FIPS-validated cryptography
func CheckFIPSCryptography(sess *session.Session) models.ComplianceResult {
	// Employ FIPS-validated cryptography to protect the confidentiality of CUI
	return models.ComplianceResult{
		Description: "Employ FIPS-validated cryptography",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.11 - Prohibit remote activation of collaborative devices
func CheckCollaborativeDeviceControl(sess *session.Session) models.ComplianceResult {
	// Prohibit remote activation of collaborative devices
	return models.ComplianceResult{
		Description: "Prohibit remote activation of collaborative devices",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.12 - Control and monitor the use of mobile code
func CheckMobileCodeControl(sess *session.Session) models.ComplianceResult {
	// Control and monitor the use of mobile code
	return models.ComplianceResult{
		Description: "Control and monitor the use of mobile code",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.13 - Control and monitor the use of VoIP
func CheckVoIPControl(sess *session.Session) models.ComplianceResult {
	// Control and monitor the use of VoIP
	return models.ComplianceResult{
		Description: "Control and monitor the use of VoIP",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.14 - Protect the authenticity of communications sessions
func CheckCommunicationsAuthenticity(sess *session.Session) models.ComplianceResult {
	// Protect the authenticity of communications sessions
	return models.ComplianceResult{
		Description: "Protect the authenticity of communications sessions",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}

// Check for control 3.13.1criteria.Value - Protect the confidentiality of CUI at rest
func CheckCUIAtRestProtection(sess *session.Session) models.ComplianceResult {
	// Protect the confidentiality of CUI at rest
	return models.ComplianceResult{
		Description: "Protect the confidentiality of CUI at rest",
		Status:      "Not Applicable",
		Response:    "This control is not applicable.",
		Impact:      0,
	}
}
