package checks

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// Mock IAM client
type mockIAMClient struct {
	iamiface.IAMAPI
	Users          []*iam.User
	PasswordPolicy *iam.PasswordPolicy
	AccountSummary map[string]*int64
}

func (m *mockIAMClient) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{Users: m.Users}, nil
}

func (m *mockIAMClient) GetAccountPasswordPolicy(input *iam.GetAccountPasswordPolicyInput) (*iam.GetAccountPasswordPolicyOutput, error) {
	return &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: m.PasswordPolicy}, nil
}

func (m *mockIAMClient) GetAccountSummary(input *iam.GetAccountSummaryInput) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{SummaryMap: m.AccountSummary}, nil
}

func (m *mockIAMClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	for _, user := range m.Users {
		if *user.UserName == *input.UserName {
			return &iam.GetUserOutput{User: user}, nil
		}
	}
	return nil, nil
}

func (m *mockIAMClient) ListMFADevices(input *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	return &iam.ListMFADevicesOutput{MFADevices: []*iam.MFADevice{{}}}, nil
}

// Mock CloudTrail client
type mockCloudTrailClient struct {
	cloudtrailiface.CloudTrailAPI
	Events []*cloudtrail.Event
}

func (m *mockCloudTrailClient) LookupEvents(input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{Events: m.Events}, nil
}

// Mock EC2 client
type mockEC2Client struct {
	ec2iface.EC2API
	Instances []*ec2.Instance
}

func (m *mockEC2Client) DescribeInstances(input *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				Instances: m.Instances,
			},
		},
	}, nil
}

func TestCheckSystemUsers(t *testing.T) {
	mockIAM := &mockIAMClient{
		Users: []*iam.User{
			{
				UserName: aws.String("test-user"),
			},
		},
	}
	mockCloudTrail := &mockCloudTrailClient{
		Events: []*cloudtrail.Event{
			{
				EventName: aws.String("RunInstances"),
			},
		},
	}
	mockEC2 := &mockEC2Client{
		Instances: []*ec2.Instance{
			{
				InstanceId: aws.String("i-12345678"),
			},
		},
	}

	result := CheckSystemUsers(mockIAM, mockCloudTrail, mockEC2)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckAuthentication(t *testing.T) {
	mockIAM := &mockIAMClient{
		Users: []*iam.User{
			{
				UserName: aws.String("test-user"),
			},
		},
	}

	result := CheckAuthentication(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckMFA(t *testing.T) {
	mockIAM := &mockIAMClient{
		Users: []*iam.User{
			{
				UserName: aws.String("test-user"),
			},
		},
	}

	result := CheckMFA(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckIdentifierReusePrevention(t *testing.T) {
	mockIAM := &mockIAMClient{
		PasswordPolicy: &iam.PasswordPolicy{
			PasswordReusePrevention: aws.Int64(1),
		},
	}

	result := CheckIdentifierReusePrevention(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckIdentifierDisabling(t *testing.T) {
	mockIAM := &mockIAMClient{
		AccountSummary: map[string]*int64{
			"AccountAccessKeysPresent": aws.Int64(0),
		},
	}

	result := CheckIdentifierDisabling(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckPasswordComplexity(t *testing.T) {
	mockIAM := &mockIAMClient{
		PasswordPolicy: &iam.PasswordPolicy{
			RequireNumbers: aws.Bool(true),
		},
	}

	result := CheckPasswordComplexity(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckPasswordReuseProhibition(t *testing.T) {
	mockIAM := &mockIAMClient{
		PasswordPolicy: &iam.PasswordPolicy{
			PasswordReusePrevention: aws.Int64(1),
		},
	}

	result := CheckPasswordReuseProhibition(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckTemporaryPasswordUsage(t *testing.T) {
	mockIAM := &mockIAMClient{
		Users: []*iam.User{
			{
				UserName:         aws.String("test-user"),
				PasswordLastUsed: aws.Time(time.Now()),
			},
		},
	}

	result := CheckTemporaryPasswordUsage(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

func TestCheckPasswordEncryption(t *testing.T) {
	mockIAM := &mockIAMClient{
		PasswordPolicy: &iam.PasswordPolicy{},
	}

	result := CheckPasswordEncryption(mockIAM)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}

// Mock IAM service
type mockIAM struct {
	iamiface.IAMAPI
}

func (m *mockIAM) GetAccountPasswordPolicy(input *iam.GetAccountPasswordPolicyInput) (*iam.GetAccountPasswordPolicyOutput, error) {
	return &iam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: &iam.PasswordPolicy{
			RequireNumbers: aws.Bool(true),
		},
	}, nil
}

func (m *mockIAM) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{
		Users: []*iam.User{
			{UserName: aws.String("user1")},
			{UserName: aws.String("user2")},
		},
	}, nil
}

func (m *mockIAM) ListMFADevices(input *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	return &iam.ListMFADevicesOutput{
		MFADevices: []*iam.MFADevice{
			{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/user1")},
		},
	}, nil
}

func TestCheckObscuredFeedback(t *testing.T) {
	mockSvc := &mockIAM{}

	result := CheckObscuredFeedback(mockSvc)
	if result.Status != "PASS" {
		t.Errorf("Expected PASS, but got %s", result.Status)
	}
}
