package discovery

import (
	"cloud_compliance_checker/models"
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// DiscoverAssets discovers assets in AWS
func DiscoverAssets(cfg aws.Config) []models.Asset {
	ec2Client := ec2.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	return discoverAssetsWithClients(ec2Client, s3Client)
}

func discoverAssetsWithClients(ec2Client *ec2.Client, s3Client *s3.Client) []models.Asset {
	var assets []models.Asset

	ec2Assets := discoverEC2Assets(ec2Client)
	s3Assets := discoverS3Assets(s3Client)

	assets = append(assets, ec2Assets...)
	assets = append(assets, s3Assets...)

	return assets
}

func discoverEC2Assets(ec2Client *ec2.Client) []models.Asset {
	var assets []models.Asset

	input := &ec2.DescribeInstancesInput{}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		log.Fatalf("failed to describe EC2 instances, %v", err)
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			asset := models.Asset{
				Name:  *instance.InstanceId,
				Type:  "EC2 Instance",
				Cloud: "AWS",
			}
			assets = append(assets, asset)
		}
	}

	return assets
}

func discoverS3Assets(s3Client *s3.Client) []models.Asset {
	var assets []models.Asset

	result, err := s3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		log.Fatalf("failed to list S3 buckets, %v", err)
	}

	for _, bucket := range result.Buckets {
		asset := models.Asset{
			Name:  *bucket.Name,
			Type:  "S3 Bucket",
			Cloud: "AWS",
		}
		assets = append(assets, asset)
	}

	return assets
}
