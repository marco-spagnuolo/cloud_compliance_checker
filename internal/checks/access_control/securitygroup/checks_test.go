package securitygroup

// import (
// 	"cloud_compliance_checker/models"
// 	"testing"

// 	"github.com/aws/aws-sdk-go/aws"
// 	"github.com/aws/aws-sdk-go/service/ec2"
// 	"github.com/stretchr/testify/assert"
// )

// func TestCheckSecurityGroup(t *testing.T) {
// 	requiredGroupName := "required-security-group"

// 	tests := []struct {
// 		name     string
// 		instance *ec2.Instance
// 		expected models.ComplianceResult
// 	}{
// 		{
// 			name: "Instance has required security group",
// 			instance: &ec2.Instance{
// 				SecurityGroups: []*ec2.GroupIdentifier{
// 					{GroupName: &requiredGroupName},
// 				},
// 			},
// 			expected: models.ComplianceResult{
// 				Description: "Instance has a specific security group",
// 				Status:      "PASS",
// 				Response:    "Implemented",
// 				Impact:      0,
// 			},
// 		},
// 		{
// 			name: "Instance does not have required security group",
// 			instance: &ec2.Instance{
// 				SecurityGroups: []*ec2.GroupIdentifier{
// 					{GroupName: aws.String("other-security-group")},
// 				},
// 			},
// 			expected: models.ComplianceResult{
// 				Description: "Instance has a specific security group",
// 				Status:      "FAIL",
// 				Response:    "Planned to be implemented",
// 				Impact:      5,
// 			},
// 		},
// 		{
// 			name: "Instance has no security groups",
// 			instance: &ec2.Instance{
// 				SecurityGroups: []*ec2.GroupIdentifier{},
// 			},
// 			expected: models.ComplianceResult{
// 				Description: "Instance has a specific security group",
// 				Status:      "FAIL",
// 				Response:    "Planned to be implemented",
// 				Impact:      5,
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			result := CheckSecurityGroup(tt.instance, models.Criteria{})
// 			assert.Equal(t, tt.expected, result)
// 		})
// 	}
// }
