package discovery

import (
	"cloud_compliance_checker/models"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

// DiscoverAssets discovers assets in AWS
func DiscoverAssets() []models.Asset {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
	})
	if err != nil {
		log.Fatalf("failed to create session, %v", err)
	}

	ec2Client := ec2.New(sess)
	s3Client := s3.New(sess)

	return discoverAssetsWithClients(ec2Client, s3Client)
}

func discoverAssetsWithClients(ec2Client ec2iface.EC2API, s3Client s3iface.S3API) []models.Asset {
	var assets []models.Asset

	ec2Assets := discoverEC2Assets(ec2Client)
	s3Assets := discoverS3Assets(s3Client)

	assets = append(assets, ec2Assets...)
	assets = append(assets, s3Assets...)

	return assets
}

func discoverEC2Assets(ec2Client ec2iface.EC2API) []models.Asset {
	var assets []models.Asset

	input := &ec2.DescribeInstancesInput{}

	result, err := ec2Client.DescribeInstances(input)
	if err != nil {
		log.Fatalf("failed to describe instances, %v", err)
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

func discoverS3Assets(s3Client s3iface.S3API) []models.Asset {
	var assets []models.Asset

	input := &s3.ListBucketsInput{}

	result, err := s3Client.ListBuckets(input)
	if err != nil {
		log.Fatalf("failed to list buckets, %v", err)
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
