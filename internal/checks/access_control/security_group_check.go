package iampolicy

import (
	"cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type SecurityGroupCheck struct {
	EC2Client *ec2.Client
}

func NewSecurityGroupCheck(cfg aws.Config) *SecurityGroupCheck {
	return &SecurityGroupCheck{
		EC2Client: ec2.NewFromConfig(cfg),
	}
}

// RunSecurityGroupCheck performs the compliance check on security groups
func RunSecurityGroupCheck(securityGroupsFromConfig []config.SecurityGroup, securityGroupsFromAWS []ec2types.SecurityGroup) error {
	isCompliant := true

	sgMap := make(map[string]config.SecurityGroup)
	for _, sg := range securityGroupsFromConfig {
		sgMap[sg.Name] = sg
	}

	for _, awsSG := range securityGroupsFromAWS {
		log.Printf("Check for security group: %s\n", *awsSG.GroupName)

		configSG, ok := sgMap[*awsSG.GroupName]
		if !ok {
			log.Printf("ERROR: Security group %s not found in the configuration file\n", *awsSG.GroupName)
			isCompliant = false
			continue
		}

		if awsSG.IpPermissions != nil {
			for _, ingress := range awsSG.IpPermissions {
				if ingress.FromPort != nil && !Contains(configSG.AllowedIngressPorts, int(*ingress.FromPort)) {
					log.Printf("Ingress port %d not allowed for group %s\n", *ingress.FromPort, *awsSG.GroupName)
					isCompliant = false
				}
			}
		}

		if awsSG.IpPermissionsEgress != nil {
			for _, egress := range awsSG.IpPermissionsEgress {
				if egress.FromPort != nil && !Contains(configSG.AllowedEgressPorts, int(*egress.FromPort)) {
					log.Printf("Egress port %d not allowed for group %s\n", *egress.FromPort, *awsSG.GroupName)
					isCompliant = false
				}
			}
		}
	}

	if !isCompliant {
		return fmt.Errorf("one or more security groups are not compliant")
	}

	return nil
}

// RunCheckCUIFlow performs the compliance checks required for NIST SP 800-171 3.1.3
func (c *IAMCheck) RunCheckCUIFlow(cfg aws.Config) error {

	securityGroupsFromConfig := config.AppConfig.AWS.SecurityGroups

	// List the security groups from AWS
	describeSGOutput, err := c.EC2Client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return LogAndReturnError("unable to list security groups", err)
	}

	// Pass the loaded data to the RunSecurityGroupCheck function
	if err := RunSecurityGroupCheck(securityGroupsFromConfig, describeSGOutput.SecurityGroups); err != nil {
		return LogAndReturnError("error during security group check", err)
	}

	log.Println("===== Security group check completed =====")

	if err := RunS3BucketCheck(cfg); err != nil {
		return LogAndReturnError("error during S3 bucket check", err)
	}
	log.Println("===== S3 bucket check completed =====")

	return nil
}
