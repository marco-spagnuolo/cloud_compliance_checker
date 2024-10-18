package integrity

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// CheckSystemFlawRemediation checks for system flaws and reports any outdated systems, missing patches, or security vulnerabilities.
func CheckSystemFlawRemediation(cfg aws.Config) error {
	ctx := context.TODO()

	// Step 1: Check EC2 instances for outdated OS/kernel versions
	log.Println("Checking EC2 instances for outdated OS or kernel versions...")
	if err := checkEC2OutdatedInstances(ctx, cfg); err != nil {
		return fmt.Errorf("EC2 instance check failed: %v", err)
	}

	// Step 2: Check for missing patches using AWS Systems Manager (SSM)
	log.Println("Checking EC2 instances for missing patches using SSM...")
	if err := checkEC2MissingPatches(ctx, cfg); err != nil {
		return fmt.Errorf("EC2 patch check failed: %v", err)
	}

	// Step 3: Check RDS for outdated engine versions or pending security updates
	log.Println("Checking RDS instances for outdated engine versions or pending security updates...")
	if err := checkRDSUpdates(ctx, cfg); err != nil {
		return fmt.Errorf("RDS check failed: %v", err)
	}

	// Step 4: Check Lambda functions for outdated runtimes
	log.Println("Checking Lambda functions for outdated runtimes...")
	if err := checkLambdaRuntimes(ctx, cfg); err != nil {
		return fmt.Errorf("Lambda runtime check failed: %v", err)
	}

	log.Println("System flaw remediation checks completed successfully.")
	return nil
}

// checkEC2OutdatedInstances checks for outdated EC2 instances by checking kernel versions or known OS vulnerabilities.
func checkEC2OutdatedInstances(ctx context.Context, cfg aws.Config) error {
	ec2Svc := ec2.NewFromConfig(cfg)

	// Describe EC2 instances
	output, err := ec2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return fmt.Errorf("unable to describe EC2 instances: %v", err)
	}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			log.Printf("Checking EC2 instance: %s (Instance Type: %s, State: %s)\n", *instance.InstanceId, instance.InstanceType, instance.State.Name)

			// Check if instance has the latest kernel or OS version (simplified logic)
			// Here you would typically check against a list of vulnerable versions
			if isOutdatedKernelOrOS(instance) {
				log.Printf("EC2 instance %s is running an outdated OS or kernel version.\n", *instance.InstanceId)
			} else {
				log.Printf("EC2 instance %s is up to date.\n", *instance.InstanceId)
			}
		}
	}

	return nil
}

func isOutdatedKernelOrOS(instance types.Instance) bool {
	// Placeholder logic - you would check specific kernel or OS versions
	return false
}

// checkEC2MissingPatches checks for missing patches on EC2 instances using AWS Systems Manager (SSM).
func checkEC2MissingPatches(ctx context.Context, cfg aws.Config) error {
	ssmSvc := ssm.NewFromConfig(cfg)

	// Step 1: Describe instances managed by SSM
	log.Println("Retrieving instances managed by SSM...")
	instanceInfoOutput, err := ssmSvc.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{})
	if err != nil {
		return fmt.Errorf("unable to describe SSM managed instances: %v", err)
	}

	if len(instanceInfoOutput.InstanceInformationList) == 0 {
		log.Println("No instances managed by SSM found.")
		return nil
	}

	// Collect instance IDs
	var instanceIDs []string
	for _, instanceInfo := range instanceInfoOutput.InstanceInformationList {
		instanceIDs = append(instanceIDs, *instanceInfo.InstanceId)
		log.Printf("Found SSM-managed EC2 instance: %s\n", *instanceInfo.InstanceId)
	}

	// Step 2: Describe patch states for each managed instance
	log.Println("Checking patch state for SSM-managed instances...")
	patchStatesOutput, err := ssmSvc.DescribeInstancePatchStates(ctx, &ssm.DescribeInstancePatchStatesInput{
		InstanceIds: instanceIDs,
	})
	if err != nil {
		return fmt.Errorf("unable to get SSM patch states: %v", err)
	}

	// Step 3: Check for missing patches
	for _, patchState := range patchStatesOutput.InstancePatchStates {
		log.Printf("Checking EC2 instance patch state: %s\n", *patchState.InstanceId)

		// Check if instance has missing patches
		if patchState.MissingCount > 0 {
			log.Printf("EC2 instance %s has %d missing patches.\n", *patchState.InstanceId, patchState.MissingCount)
		} else {
			log.Printf("EC2 instance %s is fully patched.\n", *patchState.InstanceId)
		}
	}

	return nil
}

// checkRDSUpdates checks if RDS instances are running outdated engine versions or need security updates.
func checkRDSUpdates(ctx context.Context, cfg aws.Config) error {
	rdsSvc := rds.NewFromConfig(cfg)

	// Describe RDS instances
	output, err := rdsSvc.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return fmt.Errorf("unable to describe RDS instances: %v", err)
	}

	for _, instance := range output.DBInstances {
		log.Printf("Checking RDS instance: %s (Engine: %s, Version: %s)\n", *instance.DBInstanceIdentifier, *instance.Engine, *instance.EngineVersion)

		// Check if instance has pending security updates
		if instance.PendingModifiedValues != nil {
			log.Printf("RDS instance %s has pending updates.\n", *instance.DBInstanceIdentifier)
		} else {
			log.Printf("RDS instance %s is up to date.\n", *instance.DBInstanceIdentifier)
		}
	}

	return nil
}

// checkLambdaRuntimes checks if Lambda functions are using outdated or deprecated runtimes.
func checkLambdaRuntimes(ctx context.Context, cfg aws.Config) error {
	lambdaSvc := lambda.NewFromConfig(cfg)

	// List Lambda functions
	output, err := lambdaSvc.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return fmt.Errorf("unable to list Lambda functions: %v", err)
	}

	for _, function := range output.Functions {
		log.Printf("Checking Lambda function: %s (Runtime: %s)\n", *function.FunctionName, function.Runtime)

		// Check if runtime is deprecated (simplified logic)
		if isOutdatedLambdaRuntime(string(function.Runtime)) {
			log.Printf("Lambda function %s is using a deprecated runtime: %s\n", *function.FunctionName, function.Runtime)
		} else {
			log.Printf("Lambda function %s is using a supported runtime.\n", *function.FunctionName)
		}
	}

	return nil
}

// isOutdatedLambdaRuntime checks if a Lambda function runtime is outdated (simplified logic).
func isOutdatedLambdaRuntime(runtime string) bool {
	// Placeholder logic - you would check specific deprecated runtimes
	return false
}
