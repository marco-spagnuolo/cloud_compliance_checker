package securitygroup

import (
	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/service/ec2"
)

func CheckSecurityGroup(instance *ec2.Instance) models.ComplianceResult {
	requiredGroupName := "required-security-group"
	for _, sg := range instance.SecurityGroups {
		if *sg.GroupName == requiredGroupName {
			return models.ComplianceResult{
				Description: "Instance has a specific security group",
				Status:      "PASS",
				Response:    "Implemented",
				Impact:      0,
			}
		}
	}
	return models.ComplianceResult{
		Description: "Instance has a specific security group",
		Status:      "FAIL",
		Response:    "Planned to be implemented",
		Impact:      5,
	}
}
