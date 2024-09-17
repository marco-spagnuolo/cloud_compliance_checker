package iam

import (
	"cloud_compliance_checker/models"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mocking IAMAPI interface
type mockIAMClient struct {
	iamiface.IAMAPI
	mock.Mock
}

func (m *mockIAMClient) GetInstanceProfile(input *iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*iam.GetInstanceProfileOutput), args.Error(1)
}

func (m *mockIAMClient) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*iam.ListAttachedRolePoliciesOutput), args.Error(1)
}

func (m *mockIAMClient) GetRolePolicy(input *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*iam.GetRolePolicyOutput), args.Error(1)
}

func (m *mockIAMClient) GetPolicy(input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*iam.GetPolicyOutput), args.Error(1)
}

func (m *mockIAMClient) GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*iam.GetPolicyVersionOutput), args.Error(1)
}

func TestCheckIAMRoles(t *testing.T) {
	instance := &ec2.Instance{IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")}}
	result := CheckIAMRoles(instance, models.Criteria{})
	assert.Equal(t, "Instance has IAM roles attached", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckSeparateDuties(t *testing.T) {
	instance := &ec2.Instance{IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")}}
	mockIAM := new(mockIAMClient)
	profileName := "ExampleInstanceProfile"
	input := &iam.GetInstanceProfileInput{InstanceProfileName: aws.String(profileName)}
	output := &iam.GetInstanceProfileOutput{InstanceProfile: &iam.InstanceProfile{Roles: []*iam.Role{{RoleName: aws.String("Role1")}, {RoleName: aws.String("Role2")}}}}
	mockIAM.On("GetInstanceProfile", input).Return(output, nil)

	result := CheckSeparateDuties(mockIAM, instance, models.Criteria{})
	assert.Equal(t, "Instance has roles with separate duties", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckLeastPrivilege(t *testing.T) {
	instance := &ec2.Instance{IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")}}
	mockIAM := new(mockIAMClient)
	profileName := "ExampleInstanceProfile"
	input := &iam.GetInstanceProfileInput{InstanceProfileName: aws.String(profileName)}
	output := &iam.GetInstanceProfileOutput{InstanceProfile: &iam.InstanceProfile{Roles: []*iam.Role{{RoleName: aws.String("Role1")}}}}
	mockIAM.On("GetInstanceProfile", input).Return(output, nil)

	rolePolicyInput := &iam.GetRolePolicyInput{RoleName: aws.String("Role1"), PolicyName: aws.String("PolicyName")}
	rolePolicyOutput := &iam.GetRolePolicyOutput{PolicyDocument: aws.String("{}")}
	mockIAM.On("GetRolePolicy", rolePolicyInput).Return(rolePolicyOutput, nil)

	result := CheckLeastPrivilege(mockIAM, instance, models.Criteria{})
	assert.Equal(t, "Instance uses least privilege for IAM roles", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckNonPrivilegedAccounts(t *testing.T) {
	instance := &ec2.Instance{IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")}}
	mockIAM := new(mockIAMClient)
	profileName := "ExampleInstanceProfile"
	input := &iam.GetInstanceProfileInput{InstanceProfileName: aws.String(profileName)}
	output := &iam.GetInstanceProfileOutput{InstanceProfile: &iam.InstanceProfile{Roles: []*iam.Role{{RoleName: aws.String("Role1")}}}}
	mockIAM.On("GetInstanceProfile", input).Return(output, nil)

	attachedPoliciesInput := &iam.ListAttachedRolePoliciesInput{RoleName: aws.String("Role1")}
	attachedPoliciesOutput := &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []*iam.AttachedPolicy{{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1")}}}
	mockIAM.On("ListAttachedRolePolicies", attachedPoliciesInput).Return(attachedPoliciesOutput, nil)

	policyInput := &iam.GetPolicyInput{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1")}
	policyOutput := &iam.GetPolicyOutput{Policy: &iam.Policy{DefaultVersionId: aws.String("v1")}}
	mockIAM.On("GetPolicy", policyInput).Return(policyOutput, nil)

	policyVersionInput := &iam.GetPolicyVersionInput{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1"), VersionId: aws.String("v1")}
	policyVersionOutput := &iam.GetPolicyVersionOutput{PolicyVersion: &iam.PolicyVersion{Document: aws.String("{}")}}
	mockIAM.On("GetPolicyVersion", policyVersionInput).Return(policyVersionOutput, nil)

	result := CheckNonPrivilegedAccounts(mockIAM, instance, models.Criteria{})
	assert.Equal(t, "Instance uses non-privileged roles for nonsecurity functions", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckPreventPrivilegedFunctions(t *testing.T) {
	instance := &ec2.Instance{IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")}}
	mockIAM := new(mockIAMClient)
	profileName := "ExampleInstanceProfile"
	input := &iam.GetInstanceProfileInput{InstanceProfileName: aws.String(profileName)}
	output := &iam.GetInstanceProfileOutput{InstanceProfile: &iam.InstanceProfile{Roles: []*iam.Role{{RoleName: aws.String("Role1")}}}}
	mockIAM.On("GetInstanceProfile", input).Return(output, nil)

	attachedPoliciesInput := &iam.ListAttachedRolePoliciesInput{RoleName: aws.String("Role1")}
	attachedPoliciesOutput := &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []*iam.AttachedPolicy{{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1")}}}
	mockIAM.On("ListAttachedRolePolicies", attachedPoliciesInput).Return(attachedPoliciesOutput, nil)

	policyInput := &iam.GetPolicyInput{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1")}
	policyOutput := &iam.GetPolicyOutput{Policy: &iam.Policy{DefaultVersionId: aws.String("v1")}}
	mockIAM.On("GetPolicy", policyInput).Return(policyOutput, nil)

	policyVersionInput := &iam.GetPolicyVersionInput{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1"), VersionId: aws.String("v1")}
	policyVersionOutput := &iam.GetPolicyVersionOutput{PolicyVersion: &iam.PolicyVersion{Document: aws.String("{}")}}
	mockIAM.On("GetPolicyVersion", policyVersionInput).Return(policyVersionOutput, nil)

	result := CheckPreventPrivilegedFunctions(mockIAM, instance, models.Criteria{})
	assert.Equal(t, "Instance prevents non-privileged users from executing privileged functions", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}

func TestCheckRemoteExecutionAuthorization(t *testing.T) {
	instance := &ec2.Instance{IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile")}}
	mockIAM := new(mockIAMClient)
	profileName := "ExampleInstanceProfile"
	input := &iam.GetInstanceProfileInput{InstanceProfileName: aws.String(profileName)}
	output := &iam.GetInstanceProfileOutput{InstanceProfile: &iam.InstanceProfile{Roles: []*iam.Role{{RoleName: aws.String("Role1")}}}}
	mockIAM.On("GetInstanceProfile", input).Return(output, nil)

	attachedPoliciesInput := &iam.ListAttachedRolePoliciesInput{RoleName: aws.String("Role1")}
	attachedPoliciesOutput := &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []*iam.AttachedPolicy{{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1")}}}
	mockIAM.On("ListAttachedRolePolicies", attachedPoliciesInput).Return(attachedPoliciesOutput, nil)

	policyInput := &iam.GetPolicyInput{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1")}
	policyOutput := &iam.GetPolicyOutput{Policy: &iam.Policy{DefaultVersionId: aws.String("v1")}}
	mockIAM.On("GetPolicy", policyInput).Return(policyOutput, nil)

	policyVersionInput := &iam.GetPolicyVersionInput{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Policy1"), VersionId: aws.String("v1")}
	policyVersionOutput := &iam.GetPolicyVersionOutput{PolicyVersion: &iam.PolicyVersion{Document: aws.String("{\"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"ssm:SendCommand\", \"Resource\": \"*\"}]}")}}
	mockIAM.On("GetPolicyVersion", policyVersionInput).Return(policyVersionOutput, nil)

	result := CheckRemoteExecutionAuthorization(mockIAM, instance, models.Criteria{})
	assert.Equal(t, "Instance authorizes remote execution of privileged commands", result.Description)
	assert.Equal(t, "PASS", result.Status)
	assert.Equal(t, "Implemented", result.Response)
	assert.Equal(t, 0, result.Impact)
}
