package protection

import (
	"cloud_compliance_checker/models"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// Mock EC2
type mockEC2 struct {
	ec2iface.EC2API
}

func (m *mockEC2) DescribeSecurityGroups(input *ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{
		SecurityGroups: []*ec2.SecurityGroup{
			{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []*ec2.IpPermission{
					{
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String("0.0.0.0/0"),
							},
						},
					},
				},
			},
		},
	}, nil
}

func (m *mockEC2) DescribeVpcEndpoints(input *ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
	return &ec2.DescribeVpcEndpointsOutput{
		VpcEndpoints: []*ec2.VpcEndpoint{
			{
				ServiceName: aws.String("com.amazonaws.vpce"),
			},
		},
	}, nil
}

// Mock KMS
type mockKMS struct {
	kmsiface.KMSAPI
}

func (m *mockKMS) ListKeys(input *kms.ListKeysInput) (*kms.ListKeysOutput, error) {
	return &kms.ListKeysOutput{
		Keys: []*kms.KeyListEntry{
			{
				KeyId: aws.String("key-12345"),
			},
		},
	}, nil
}

func TestCheckBoundaryProtection(t *testing.T) {
	sess := &session.Session{}
	mockEC2 := &mockEC2{}

	CheckBoundaryProtectionWithService := func(sess *session.Session, ec2Svc ec2iface.EC2API) models.ComplianceResult {
		input := &ec2.DescribeSecurityGroupsInput{}
		result, err := ec2Svc.DescribeSecurityGroups(input)
		if err != nil {
			return models.ComplianceResult{
				Description: "Ensure network boundaries are protected",
				Status:      "FAIL",
				Response:    "Error describing security groups",
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

	result := CheckBoundaryProtectionWithService(sess, mockEC2)
	if result.Status != "FAIL" {
		t.Errorf("Expected FAIL, but got %s", result.Status)
	}
}

func TestCheckCryptographicProtection(t *testing.T) {
	sess := &session.Session{}
	mockKMS := &mockKMS{}

	CheckCryptographicProtectionWithService := func(sess *session.Session, kmsSvc kmsiface.KMSAPI) models.ComplianceResult {
		input := &kms.ListKeysInput{}
		result, err := kmsSvc.ListKeys(input)
		if err != nil {
			return models.ComplianceResult{
				Description: "Ensure communication channels are encrypted",
				Status:      "FAIL",
				Response:    "Error listing KMS keys",
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

	result := CheckCryptographicProtectionWithService(sess, mockKMS)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckInformationTransmissionProtection(t *testing.T) {
	sess := &session.Session{}
	mockEC2 := &mockEC2{}

	CheckInformationTransmissionProtectionWithService := func(sess *session.Session, ec2Svc ec2iface.EC2API) models.ComplianceResult {
		input := &ec2.DescribeVpcEndpointsInput{}
		result, err := ec2Svc.DescribeVpcEndpoints(input)
		if err != nil {
			return models.ComplianceResult{
				Description: "Ensure information is protected during transmission",
				Status:      "FAIL",
				Response:    "Error describing VPC endpoints",
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

	result := CheckInformationTransmissionProtectionWithService(sess, mockEC2)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}
