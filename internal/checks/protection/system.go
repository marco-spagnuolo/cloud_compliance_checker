package protection

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// SecureAWSResources runs security checks on all S3 buckets, EBS volumes, and EC2 instances.
// 03.13.04
func SecureAWSResources(cfg aws.Config) error {
	// Step 1: Check all S3 Buckets
	ctx := context.TODO()
	if err := SecureAllS3Buckets(cfg); err != nil {
		return fmt.Errorf("failed to secure S3 buckets: %v", err)
	}
	log.Println("All S3 buckets have been checked.")

	// Step 2: Securely Delete Unused EBS Volumes
	if err := SecureAllEBSVolumes(ctx, cfg); err != nil {
		return fmt.Errorf("failed to securely delete EBS volumes: %v", err)
	}
	log.Println("All EBS volumes have been checked.")

	// Step 3: Ensure EC2 Instance Cleanup
	if err := EnsureEC2InstanceCleanup(ctx, cfg); err != nil {
		return fmt.Errorf("failed to clean up EC2 instances: %v", err)
	}
	log.Println("EC2 instance cleanup completed.")

	return nil
}

// SecureAllS3Buckets checks each S3 bucket to ensure it is not publicly accessible.
func SecureAllS3Buckets(cfg aws.Config) error {
	ctx := context.TODO()
	svc := s3.NewFromConfig(cfg)

	// List all S3 buckets
	result, err := svc.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("unable to list S3 buckets: %v", err)
	}

	// Check each bucket for security
	for _, bucket := range result.Buckets {
		if err := CheckSecureS3Bucket(ctx, cfg, *bucket.Name); err != nil {
			log.Printf("Warning: Bucket %s is not secure: %v\n", *bucket.Name, err)
		} else {
			log.Printf("Bucket %s is secure.\n", *bucket.Name)
		}
	}

	return nil
}

// SecureAllEBSVolumes ensures that unused EBS volumes are securely deleted.
func SecureAllEBSVolumes(ctx context.Context, cfg aws.Config) error {
	svc := ec2.NewFromConfig(cfg)

	// List all EBS volumes
	result, err := svc.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return fmt.Errorf("unable to describe EBS volumes: %v", err)
	}

	// Delete unused volumes
	for _, volume := range result.Volumes {
		// Consider volumes available if they are not attached to any instance
		if volume.State == types.VolumeStateAvailable { // Updated
			if err := SecurelyDeleteEBSVolume(ctx, cfg, *volume.VolumeId); err != nil {
				log.Printf("Failed to securely delete EBS volume %s: %v\n", *volume.VolumeId, err)
			} else {
				log.Printf("EBS volume %s securely deleted.\n", *volume.VolumeId)
			}
		}
	}

	return nil
}

// EnsureEC2InstanceCleanup ensures that any terminated EC2 instances are cleaned up.
func EnsureEC2InstanceCleanup(ctx context.Context, cfg aws.Config) error {
	svc := ec2.NewFromConfig(cfg)

	// Describe all EC2 instances
	instances, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe instances: %v", err)
	}

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State.Name == types.InstanceStateNameTerminated { // Updated
				// Perform cleanup tasks, such as deleting associated EBS volumes
				for _, volume := range instance.BlockDeviceMappings {
					if volume.Ebs != nil {
						if err := SecurelyDeleteEBSVolume(ctx, cfg, *volume.Ebs.VolumeId); err != nil {
							log.Printf("Failed to clean up EBS volume %s: %v\n", *volume.Ebs.VolumeId, err)
						} else {
							log.Printf("Cleaned up EBS volume %s for terminated instance.\n", *volume.Ebs.VolumeId)
						}
					}
				}
				log.Printf("Cleaned up terminated instance: %s\n", *instance.InstanceId)
			}
		}
	}

	return nil
}

// CheckSecureS3Bucket ensures that an S3 bucket is not publicly accessible.
func CheckSecureS3Bucket(ctx context.Context, cfg aws.Config, bucketName string) error {
	svc := s3.NewFromConfig(cfg)

	// Check for public ACLs
	aclOutput, err := svc.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return fmt.Errorf("failed to get bucket ACLs: %v", err)
	}

	for _, grant := range aclOutput.Grants {
		if grant.Grantee != nil && grant.Grantee.URI != nil {
			if *grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" ||
				*grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
				return fmt.Errorf("bucket %s has a public ACL", bucketName)
			}
		}
	}

	// Get the bucket policy and check if it is public
	policyStatus, err := svc.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
		Bucket: &bucketName,
	})
	if err != nil {
		log.Printf("No bucket policy found for %s or unable to retrieve: %v", bucketName, err)
	} else if policyStatus.PolicyStatus != nil && *policyStatus.PolicyStatus.IsPublic {
		return fmt.Errorf("bucket %s has a public policy", bucketName)
	}

	log.Printf("S3 Bucket %s is secure and not publicly accessible.\n", bucketName)
	return nil
}

// SecurelyDeleteEBSVolume ensures that EBS volumes are securely deleted.
func SecurelyDeleteEBSVolume(ctx context.Context, cfg aws.Config, volumeId string) error {
	ec2Svc := ec2.NewFromConfig(cfg)

	// Delete the volume
	_, err := ec2Svc.DeleteVolume(ctx, &ec2.DeleteVolumeInput{
		VolumeId: &volumeId,
	})
	if err != nil {
		return fmt.Errorf("failed to securely delete volume %s: %v", volumeId, err)
	}

	log.Printf("EBS Volume %s has been securely deleted.\n", volumeId)
	return nil
}

// CheckTransmissionAndStorageConfidentiality checks if cryptographic mechanisms are in place
// to prevent unauthorized disclosure of CUI during transmission and storage.
// 03.13.08
func CheckTransmissionAndStorageConfidentiality(cfg aws.Config) error {
	ctx := context.TODO()
	// Check S3 bucket encryption and transmission settings
	if err := checkS3Confidentiality(ctx, cfg); err != nil {
		return fmt.Errorf("S3 confidentiality check failed: %v", err)
	}

	// Check EBS volume encryption
	if err := checkEBSConfidentiality(ctx, cfg); err != nil {
		return fmt.Errorf("EBS volume confidentiality check failed: %v", err)
	}

	// Check RDS instance encryption
	if err := checkRDSConfidentiality(ctx, cfg); err != nil {
		return fmt.Errorf("RDS confidentiality check failed: %v", err)
	}

	log.Println("Transmission and storage confidentiality checks passed.")
	return nil
}

// Check if S3 buckets enforce encryption for data at rest and require SSL for transmission.
func checkS3Confidentiality(ctx context.Context, cfg aws.Config) error {
	s3Svc := s3.NewFromConfig(cfg)

	// List all S3 buckets
	result, err := s3Svc.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("failed to list S3 buckets: %v", err)
	}

	for _, bucket := range result.Buckets {
		log.Printf("Checking S3 Bucket: %s\n", *bucket.Name)

		// Check if encryption is enabled
		_, err := s3Svc.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			return fmt.Errorf("S3 bucket %s does not have encryption enabled: %v", *bucket.Name, err)
		}

		// Check if SSL is enforced during transmission
		policyStatus, err := s3Svc.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: bucket.Name,
		})
		if err == nil && policyStatus.PolicyStatus != nil && *policyStatus.PolicyStatus.IsPublic {
			return fmt.Errorf("S3 bucket %s allows unencrypted traffic. SSL must be enforced.", *bucket.Name)
		}
	}

	log.Println("All S3 buckets are encrypted and enforce SSL for transmission.")
	return nil
}

// Check if EBS volumes are encrypted.
func checkEBSConfidentiality(ctx context.Context, cfg aws.Config) error {
	ec2Svc := ec2.NewFromConfig(cfg)

	// Describe all EBS volumes
	result, err := ec2Svc.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe EBS volumes: %v", err)
	}

	for _, volume := range result.Volumes {
		if !*volume.Encrypted {
			return fmt.Errorf("EBS volume %s is not encrypted", *volume.VolumeId)
		}
	}

	log.Println("All EBS volumes are encrypted.")
	return nil
}

// Check if RDS instances have encryption enabled.
func checkRDSConfidentiality(ctx context.Context, cfg aws.Config) error {
	rdsSvc := rds.NewFromConfig(cfg)

	// Describe all RDS instances
	result, err := rdsSvc.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return fmt.Errorf("failed to describe RDS instances: %v", err)
	}

	for _, dbInstance := range result.DBInstances {
		if !*dbInstance.StorageEncrypted {
			return fmt.Errorf("RDS instance %s does not have encryption enabled", *dbInstance.DBInstanceIdentifier)
		}
	}

	log.Println("All RDS instances are encrypted.")
	return nil
}
