package protection

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types" // Add types import
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// SecureAWSResources runs security checks on all S3 buckets, EBS volumes, and EC2 instances.
// 03.13.04
func SecureAWSResources(cfg aws.Config) error {
	// Step 1: Check all S3 Buckets
	ctx := context.TODO()
	if err := SecureAllS3Buckets(ctx, cfg); err != nil {
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
func SecureAllS3Buckets(ctx context.Context, cfg aws.Config) error {
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
