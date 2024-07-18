package discovery

import (
	"cloud_compliance_checker/models"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/assert"
)

// Mock EC2 client
type mockEC2Client struct {
	ec2iface.EC2API
}

func (m *mockEC2Client) DescribeInstances(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				Instances: []*ec2.Instance{
					{
						InstanceId: aws.String("i-1234567890abcdef0"),
					},
				},
			},
		},
	}, nil
}

// Mock S3 client
type mockS3Client struct {
	s3iface.S3API
}

func (m *mockS3Client) ListBuckets(*s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{
		Buckets: []*s3.Bucket{
			{
				Name: aws.String("test-bucket"),
			},
		},
	}, nil
}

// Test for DiscoverAssets
func TestDiscoverAssets(t *testing.T) {
	ec2Client := &mockEC2Client{}
	s3Client := &mockS3Client{}

	assets := discoverAssetsWithClients(ec2Client, s3Client)
	assert.Equal(t, 2, len(assets))

	expectedAssets := []models.Asset{
		{Name: "i-1234567890abcdef0", Type: "EC2 Instance", Cloud: "AWS"},
		{Name: "test-bucket", Type: "S3 Bucket", Cloud: "AWS"},
	}

	assert.ElementsMatch(t, expectedAssets, assets)
}
