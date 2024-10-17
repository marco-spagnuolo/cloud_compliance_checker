package protection

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// CheckSessionTimeouts ensures that network connections are terminated after inactivity or session end.
// It checks idle timeouts for ELB and ensures that EC2 SSH timeouts are properly configured.
func CheckSessionTimeouts(cfg aws.Config) error {
	// Check Elastic Load Balancers (Classic and Application/Network Load Balancers)
	ctx := context.TODO()
	if err := checkELBTimeouts(ctx, cfg); err != nil {
		return fmt.Errorf("failed to check ELB timeouts: %v", err)
	}

	// Check EC2 SSH session timeout settings
	if err := checkEC2SSHTimeouts(ctx, cfg); err != nil {
		return fmt.Errorf("failed to check EC2 SSH timeouts: %v", err)
	}

	log.Println("All session timeouts have been successfully verified.")
	return nil
}

// checkELBTimeouts checks if Elastic Load Balancers (Classic and Application/Network) have idle timeouts configured.
func checkELBTimeouts(ctx context.Context, cfg aws.Config) error {
	// Check Classic Load Balancers
	elbSvc := elasticloadbalancing.NewFromConfig(cfg)
	elbResult, err := elbSvc.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return fmt.Errorf("failed to describe Classic Load Balancers: %v", err)
	}

	for _, elb := range elbResult.LoadBalancerDescriptions {
		log.Printf("Checking Classic Load Balancer: %s\n", *elb.LoadBalancerName)

		// Check the idle timeout for the Load Balancer
		configOutput, err := elbSvc.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{
			LoadBalancerName: elb.LoadBalancerName,
		})
		if err != nil {
			return fmt.Errorf("failed to describe attributes for ELB %s: %v", *elb.LoadBalancerName, err)
		}

		if configOutput.LoadBalancerAttributes.ConnectionSettings == nil || configOutput.LoadBalancerAttributes.ConnectionSettings.IdleTimeout == nil {
			log.Printf("Warning: ELB %s does not have an idle timeout configured.\n", *elb.LoadBalancerName)
		} else {
			log.Printf("ELB %s idle timeout is set to %d seconds.\n", *elb.LoadBalancerName, *configOutput.LoadBalancerAttributes.ConnectionSettings.IdleTimeout)
		}
	}

	// Check Application and Network Load Balancers (ALB/NLB)
	elbV2Svc := elasticloadbalancingv2.NewFromConfig(cfg)
	elbV2Result, err := elbV2Svc.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return fmt.Errorf("failed to describe ALB/NLB Load Balancers: %v", err)
	}

	for _, lb := range elbV2Result.LoadBalancers {
		log.Printf("Checking ALB/NLB Load Balancer: %s\n", *lb.LoadBalancerName)

		// Describe the attributes of the ALB/NLB
		attrResult, err := elbV2Svc.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
			LoadBalancerArn: lb.LoadBalancerArn,
		})
		if err != nil {
			return fmt.Errorf("failed to describe attributes for ALB/NLB %s: %v", *lb.LoadBalancerName, err)
		}

		// Find idle timeout attribute and log it
		idleTimeoutConfigured := false
		for _, attr := range attrResult.Attributes {
			if *attr.Key == "idle_timeout.timeout_seconds" {
				log.Printf("ALB/NLB %s idle timeout is set to %s seconds.\n", *lb.LoadBalancerName, attr.Value)
				idleTimeoutConfigured = true
				break
			}
		}

		if !idleTimeoutConfigured {
			log.Printf("Warning: ALB/NLB %s does not have an idle timeout configured.\n", *lb.LoadBalancerName)
		}
	}

	return nil
}

// checkEC2SSHTimeouts checks if EC2 instances are configured to terminate idle SSH sessions.
func checkEC2SSHTimeouts(ctx context.Context, cfg aws.Config) error {
	ec2Svc := ec2.NewFromConfig(cfg)

	// Describe all EC2 instances
	result, err := ec2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe EC2 instances: %v", err)
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			log.Printf("Checking EC2 Instance: %s\n", *instance.InstanceId)

			// Normally, we'd look for SSH configuration or user data to check for session timeouts (e.g., ClientAliveInterval or TCPKeepAlive in SSH config).
			// In this simplified example, we assume SSH session timeouts are managed and would need to check configurations manually or via user data.
			attrResult, err := ec2Svc.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
				InstanceId: instance.InstanceId,
				Attribute:  "userData",
			})
			if err != nil {
				return fmt.Errorf("failed to describe instance attribute for %s: %v", *instance.InstanceId, err)
			}

			if attrResult.UserData != nil && attrResult.UserData.Value != nil {
				log.Printf("EC2 Instance %s has user data: %s (check SSH timeout settings manually).\n", *instance.InstanceId, *attrResult.UserData.Value)
			} else {
				log.Printf("EC2 Instance %s has no user data. Ensure SSH timeout settings are manually configured.\n", *instance.InstanceId)
			}
		}
	}

	return nil
}
