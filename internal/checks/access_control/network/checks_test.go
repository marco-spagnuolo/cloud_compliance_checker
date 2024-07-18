package network

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock for EC2API interface
type mockEC2Client struct {
	mock.Mock
	ec2iface.EC2API
}

func (m *mockEC2Client) DescribeFlowLogs(input *ec2.DescribeFlowLogsInput) (*ec2.DescribeFlowLogsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*ec2.DescribeFlowLogsOutput), args.Error(1)
}

func (m *mockEC2Client) DescribeSecurityGroups(input *ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*ec2.DescribeSecurityGroupsOutput), args.Error(1)
}

// Test for CheckFlowLogs function
func TestCheckFlowLogs(t *testing.T) {
	mockSvc := new(mockEC2Client)
	instance := &ec2.Instance{VpcId: aws.String("vpc-1234")}

	input := &ec2.DescribeFlowLogsInput{
		Filter: []*ec2.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []*string{aws.String("vpc-1234")},
			},
		},
	}
	output := &ec2.DescribeFlowLogsOutput{
		FlowLogs: []*ec2.FlowLog{
			{FlowLogId: aws.String("fl-1234")},
		},
	}

	mockSvc.On("DescribeFlowLogs", input).Return(output, nil)

	result := CheckFlowLogs(mockSvc, instance)

	assert.Equal(t, "Instance has flow logs enabled", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

// Test for CheckRemoteAccessMonitoring function
func TestCheckRemoteAccessMonitoring(t *testing.T) {
	instance := &ec2.Instance{}
	success, err := checkAuditdConfiguration()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if success {
		result := CheckRemoteAccessMonitoring(instance)
		assert.Equal(t, "Instance monitors and controls remote access sessions", result.Description)
		assert.Equal(t, "PASS", result.Status)
		assert.Equal(t, "Implemented", result.Response)
		assert.Equal(t, 0, result.Impact)
	} else {
		result := CheckRemoteAccessMonitoring(instance)
		assert.Equal(t, "Instance monitors and controls remote access sessions", result.Description)
		assert.Equal(t, "FAIL", result.Status)
		assert.Equal(t, "auditd not properly configured for remote access monitoring", result.Response)
		assert.Equal(t, 5, result.Impact)
	}
}

// Test for CheckRemoteAccessEncryption function
func TestCheckRemoteAccessEncryption(t *testing.T) {
	instance := &ec2.Instance{}
	success, err := checkSSHEcryptionConfiguration()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if success {
		result := CheckRemoteAccessEncryption(instance)
		assert.Equal(t, "Instance uses encryption for remote access sessions", result.Description)
		assert.Equal(t, "PASS", result.Status)
		assert.Equal(t, "Implemented", result.Response)
		assert.Equal(t, 0, result.Impact)
	} else {
		result := CheckRemoteAccessEncryption(instance)
		assert.Equal(t, "Instance uses encryption for remote access sessions", result.Description)
		assert.Equal(t, "FAIL", result.Status)
		assert.Equal(t, "SSH not properly configured for encryption", result.Response)
		assert.Equal(t, 5, result.Impact)
	}
}

// Test for CheckRemoteAccessRouting function
func TestCheckRemoteAccessRouting(t *testing.T) {
	mockSvc := new(mockEC2Client)
	instance := &ec2.Instance{
		SecurityGroups: []*ec2.GroupIdentifier{
			{GroupId: aws.String("sg-1234")},
		},
	}

	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{aws.String("sg-1234")},
	}
	output := &ec2.DescribeSecurityGroupsOutput{
		SecurityGroups: []*ec2.SecurityGroup{
			{
				GroupId: aws.String("sg-1234"),
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(22),
						ToPort:     aws.Int64(22),
						IpRanges: []*ec2.IpRange{
							{CidrIp: aws.String("1.1.1.1/32")},
						},
					},
				},
			},
		},
	}

	mockSvc.On("DescribeSecurityGroups", input).Return(output, nil)

	result := CheckRemoteAccessRouting(mockSvc, instance)

	assert.Equal(t, "Instance routes remote access via managed access control points", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

// Test for CheckWirelessAccessAuthorization function
func TestCheckWirelessAccessAuthorization(t *testing.T) {
	instance := &ec2.Instance{}
	result := CheckWirelessAccessAuthorization(instance)

	assert.Equal(t, "Instance authorizes wireless access before connections", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

// Test for CheckWirelessAccessProtection function
func TestCheckWirelessAccessProtection(t *testing.T) {
	instance := &ec2.Instance{}
	result := CheckWirelessAccessProtection(instance)

	assert.Equal(t, "Instance uses authentication and encryption for wireless access", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}
