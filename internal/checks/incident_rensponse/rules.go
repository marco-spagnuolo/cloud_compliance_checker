package incident_response

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Revoke all ingress and egress rules for the specified security group
func revokeIngressEgressRules(svc *ec2.Client, groupID *string) error {
	// Ingress rules
	ingressRevoke := &ec2.RevokeSecurityGroupIngressInput{
		GroupId: groupID,
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
		},
	}
	_, err := svc.RevokeSecurityGroupIngress(context.TODO(), ingressRevoke)
	if err != nil && !strings.Contains(err.Error(), "InvalidPermission.NotFound") {
		return err
	}

	// Egress rules
	egressRevoke := &ec2.RevokeSecurityGroupEgressInput{
		GroupId: groupID,
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
		},
	}
	_, err = svc.RevokeSecurityGroupEgress(context.TODO(), egressRevoke)
	if err != nil && !strings.Contains(err.Error(), "InvalidPermission.NotFound") {
		return err
	}

	return nil
}

// Restore ingress rules for the security group
func restoreIngressRules(svc *ec2.Client, groupID *string) error {
	ingressRule := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: groupID,
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("-1"), // All protocols
				IpRanges: []ec2types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"), // All IPs
					},
				},
			},
		},
	}

	_, err := svc.AuthorizeSecurityGroupIngress(context.TODO(), ingressRule)
	if err != nil && !strings.Contains(err.Error(), "InvalidPermission.Duplicate") {
		return err
	}

	fmt.Println("Ingress rule restored successfully.")
	return nil
}

// Restore egress rules for the security group
func restoreEgressRules(svc *ec2.Client, groupID *string) error {
	egressRule := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: groupID,
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("-1"), // All protocols
				IpRanges: []ec2types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"), // All IPs
					},
				},
			},
		},
	}

	_, err := svc.AuthorizeSecurityGroupEgress(context.TODO(), egressRule)
	if err != nil && !strings.Contains(err.Error(), "InvalidPermission.Duplicate") {
		return err
	}

	fmt.Println("Egress rule restored successfully.")
	return nil
}
