package iampolicy

import (
	"cloud_compliance_checker/config"
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Check struct {
	S3Client *s3.Client
}

func NewS3Check(cfg aws.Config) *S3Check {
	return &S3Check{
		S3Client: s3.NewFromConfig(cfg),
	}
}

// RunS3BucketCheck performs the compliance check on S3 buckets
func RunS3BucketCheck(cfg aws.Config) error {

	s3Check := NewS3Check(cfg)

	bucketsFromConfig := config.AppConfig.AWS.S3Buckets
	listBucketsOutput, err := s3Check.S3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		return LogAndReturnError("unable to list buckets", err)
	}

	bucketMap := make(map[string]config.S3Bucket)
	for _, bucket := range bucketsFromConfig {
		bucketMap[bucket.Name] = bucket
	}

	for _, awsBucket := range listBucketsOutput.Buckets {
		if awsBucket.Name == nil {
			continue
		}
		log.Printf("Check for S3 bucket: %s\n", *awsBucket.Name)

		_, ok := bucketMap[*awsBucket.Name]
		if !ok {
			return LogAndReturnError("one or more S3 buckets are not compliant", errors.New(fmt.Sprintf("ERROR: S3 bucket %s not found in the configuration file\n", *awsBucket.Name)))
		}

	}

	return nil
}
