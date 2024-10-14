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

// UnisolateInstance rimuove il gruppo di sicurezza di isolamento e ripristina i gruppi di sicurezza originali
func UnisolateInstance(cfg aws.Config, instanceID string, originalSecurityGroupIDs []string) error {
	svc := ec2.NewFromConfig(cfg)

	// Rimuovi il gruppo di sicurezza di isolamento (es: "quarantine") e ripristina i gruppi di sicurezza originali
	input := &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		Groups:     originalSecurityGroupIDs, // Ripristina i gruppi di sicurezza originali
	}

	_, err := svc.ModifyInstanceAttribute(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to restore original security groups: %v", err)
	}

	fmt.Println("Instance successfully un-isolated and original security groups restored.")
	return nil
}

func IsolateInstanceWithSecurityGroupByName(cfg aws.Config, instanceID, securityGroupName string) error {
	// Trova il Security Group tramite il nome
	groupID, err := FindSecurityGroupByName(cfg, securityGroupName)
	if err != nil {
		return fmt.Errorf("failed to find security group by name: %v", err)
	}

	// Ora applica il Security Group all'istanza
	return IsolateInstanceWithSecurityGroup(cfg, instanceID, groupID)
}

// IsolateInstanceWithSecurityGroup associa il Security Group trovato all'istanza per isolarla
func IsolateInstanceWithSecurityGroup(cfg aws.Config, instanceID, groupID string) error {
	svc := ec2.NewFromConfig(cfg)

	// Associa il gruppo di sicurezza di isolamento all'istanza
	input := &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		Groups:     []string{groupID},
	}

	_, err := svc.ModifyInstanceAttribute(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to apply quarantine security group: %v", err)
	}

	fmt.Println("Instance successfully isolated with security group:", groupID)
	return nil
}

// FindSecurityGroupByName cerca un Security Group tramite il suo nome
func FindSecurityGroupByName(cfg aws.Config, groupName string) (string, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []string{groupName},
			},
		},
	}

	// Chiamata API DescribeSecurityGroups per trovare il gruppo di sicurezza
	output, err := svc.DescribeSecurityGroups(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe security groups: %v", err)
	}

	// Verifica se c'è almeno un gruppo di sicurezza trovato
	for _, sg := range output.SecurityGroups {
		return *sg.GroupId, nil
	}

	return "", fmt.Errorf("no security group found with name %s", groupName)
}
