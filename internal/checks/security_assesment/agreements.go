package security_assesment

import (
	config "cloud_compliance_checker/config"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func CheckExchangeAgreements(awsCfg aws.Config) error {
	bucketName := config.AppConfig.AWS.SecurityAssessmentConfig.S3BucketName
	log.Println("Checking for existing CUI exchange agreements...")
	svc := s3.NewFromConfig(awsCfg)

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String("agreements/"),
	}

	resp, err := svc.ListObjectsV2(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("error retrieving agreements: %v", err)
	}

	if len(resp.Contents) == 0 {
		return fmt.Errorf("[ERROR]: No CUI exchange agreements found in the specified bucket. Ensure agreements are documented and managed")
	}

	log.Println("CUI exchange agreements found:")
	for _, item := range resp.Contents {
		log.Printf(" - %s (Last modified: %s)\n", *item.Key, item.LastModified)

		// Check if the object is encrypted
		encStatus, err := CheckObjectEncryption(svc, bucketName, *item.Key)
		log.Printf("Bucket Name: %s, encStatus: %v", bucketName, encStatus)
		if err != nil {
			return fmt.Errorf("failed to check encryption for %s: %v", *item.Key, err)
		}
		if !encStatus {
			log.Printf("[WARNING]: Object %s is not encrypted. Ensure sensitive data is encrypted.\n", *item.Key)
		}
	}

	return nil
}

// CheckObjectEncryption verifies if an S3 object is encrypted
func CheckObjectEncryption(svc *s3.Client, bucketName, key string) (bool, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	}

	resp, err := svc.GetObject(context.TODO(), input)
	if err != nil {
		return false, fmt.Errorf("error retrieving object metadata: %v", err)
	}

	// Check for server-side encryption
	if resp.ServerSideEncryption == types.ServerSideEncryptionAwsKms || resp.ServerSideEncryption == types.ServerSideEncryptionAes256 {
		return true, nil
	}

	return false, nil
}
