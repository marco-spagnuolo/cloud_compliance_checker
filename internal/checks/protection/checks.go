package protection

import (
	"cloud_compliance_checker/models"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/kms"
)

// Check for control 3.13.1 - Ensure network boundaries are protected
func CheckBoundaryProtection(sess *session.Session) models.ComplianceResult {
	ec2Svc := ec2.New(sess)

	input := &ec2.DescribeSecurityGroupsInput{}
	result, err := ec2Svc.DescribeSecurityGroups(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure network boundaries are protected",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error describing security groups: %v", err),
			Impact:      5,
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
						Impact:      5,
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
func CheckCryptographicProtection(sess *session.Session) models.ComplianceResult {
	kmsSvc := kms.New(sess)

	input := &kms.ListKeysInput{}
	result, err := kmsSvc.ListKeys(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure communication channels are encrypted",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error listing KMS keys: %v", err),
			Impact:      5,
		}
	}

	if len(result.Keys) == 0 {
		return models.ComplianceResult{
			Description: "Ensure communication channels are encrypted",
			Status:      "FAIL",
			Response:    "No KMS keys found for encryption",
			Impact:      5,
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
func CheckInformationTransmissionProtection(sess *session.Session) models.ComplianceResult {
	ec2Svc := ec2.New(sess)

	input := &ec2.DescribeVpcEndpointsInput{}
	result, err := ec2Svc.DescribeVpcEndpoints(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Ensure information is protected during transmission",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error describing VPC endpoints: %v", err),
			Impact:      5,
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
		Impact:      5,
	}
}
