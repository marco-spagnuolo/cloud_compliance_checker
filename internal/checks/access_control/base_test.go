package checks_test

import (
	checks "cloud_compliance_checker/internal/checks/access_control"
	"cloud_compliance_checker/internal/utils"
	"cloud_compliance_checker/models"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock IAM client
type mockIAMClient struct {
	iamiface.IAMAPI
	mock.Mock
}

func (m *mockIAMClient) GetInstanceProfile(input *iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*iam.GetInstanceProfileOutput), args.Error(1)
}

// Mock EC2 client
type mockEC2Client struct {
	ec2iface.EC2API
	mock.Mock
}

func (m *mockEC2Client) DescribeFlowLogs(input *ec2.DescribeFlowLogsInput) (*ec2.DescribeFlowLogsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*ec2.DescribeFlowLogsOutput), args.Error(1)
}

func TestEvaluateCriteria(t *testing.T) {
	instance := &ec2.Instance{
		IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")},
	}

	ec2Client := new(mockEC2Client)
	iamClient := new(mockIAMClient)

	// Mock EC2 Flow Logs
	flowLogsOutput := &ec2.DescribeFlowLogsOutput{
		FlowLogs: []*ec2.FlowLog{
			{
				FlowLogId: aws.String("fl-12345678"),
			},
		},
	}
	ec2Client.On("DescribeFlowLogs", mock.Anything).Return(flowLogsOutput, nil)

	// Mock IAM Instance Profile
	instanceProfileOutput := &iam.GetInstanceProfileOutput{
		InstanceProfile: &iam.InstanceProfile{
			Roles: []*iam.Role{
				{RoleName: aws.String("TestRole")},
			},
		},
	}
	iamClient.On("GetInstanceProfile", mock.Anything).Return(instanceProfileOutput, nil)

	controls := utils.NISTControls{
		Controls: []utils.Control{
			{
				Criteria: []utils.Criteria{
					{CheckFunction: "CheckFlowLogs"},
					{CheckFunction: "CheckIAMRoles"},
				},
			},
		},
	}

	expectedResults := []models.ComplianceResult{
		{Description: "Instance has flow logs enabled", Status: "PASS", Response: "Implemented", Impact: 0},
		{Description: "Instance has IAM roles attached", Status: "PASS", Response: "Implemented", Impact: 0},
	}

	for i, criteria := range controls.Controls[0].Criteria {
		result := checks.EvaluateCriteria(instance, criteria, ec2Client, iamClient)
		assert.Equal(t, expectedResults[i].Description, result.Description)
		assert.Equal(t, expectedResults[i].Status, result.Status)
		assert.Equal(t, expectedResults[i].Response, result.Response)
		assert.Equal(t, expectedResults[i].Impact, result.Impact)
	}
}

func TestCheckCompliance(t *testing.T) {
	instance := &ec2.Instance{
		IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")},
	}

	ec2Client := new(mockEC2Client)
	iamClient := new(mockIAMClient)

	// Mock EC2 Flow Logs
	flowLogsOutput := &ec2.DescribeFlowLogsOutput{
		FlowLogs: []*ec2.FlowLog{
			{
				FlowLogId: aws.String("fl-12345678"),
			},
		},
	}
	ec2Client.On("DescribeFlowLogs", mock.Anything).Return(flowLogsOutput, nil)

	// Mock IAM Instance Profile
	instanceProfileOutput := &iam.GetInstanceProfileOutput{
		InstanceProfile: &iam.InstanceProfile{
			Roles: []*iam.Role{
				{RoleName: aws.String("TestRole")},
			},
		},
	}
	iamClient.On("GetInstanceProfile", mock.Anything).Return(instanceProfileOutput, nil)

	controls := utils.NISTControls{
		Controls: []utils.Control{
			{
				Criteria: []utils.Criteria{
					{CheckFunction: "CheckFlowLogs"},
					{CheckFunction: "CheckIAMRoles"},
				},
			},
		},
	}

	score := checks.CheckCompliance(instance, controls, ec2Client, iamClient)
	assert.Equal(t, 110, score)
}
