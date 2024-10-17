package protection

import (
	"cloud_compliance_checker/config"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CheckMobileCode checks for proper controls and monitoring of mobile code in S3 and CloudFront.
func CheckMobileCode(cfg aws.Config) error {
	ctx := context.Background()
	log.Println("Starting mobile code checks...")

	// Check IAM policies for mobile code upload control
	log.Println("Checking IAM policies for mobile code controls...")
	if err := checkIAMForMobileCode(ctx, cfg); err != nil {
		return fmt.Errorf("IAM policy check for mobile code failed: %v", err)
	}
	log.Println("IAM policy checks completed.")

	// Check S3 buckets for mobile code
	log.Println("Checking S3 buckets for mobile code...")
	if err := checkS3BucketsForMobileCode(ctx, cfg); err != nil {
		return fmt.Errorf("S3 bucket check for mobile code failed: %v", err)
	}
	log.Println("S3 bucket checks completed.")

	// Check CloudFront distributions for mobile code usage
	log.Println("Checking CloudFront distributions for mobile code...")
	if err := checkCloudFrontForMobileCode(ctx, cfg); err != nil {
		return fmt.Errorf("CloudFront check for mobile code failed: %v", err)
	}
	log.Println("CloudFront checks completed.")

	log.Println("Mobile code check completed successfully.")
	return nil
}

// checkIAMForMobileCode checks if the IAM policies are properly configured to control mobile code uploads.
func checkIAMForMobileCode(ctx context.Context, cfg aws.Config) error {
	iamSvc := iam.NewFromConfig(cfg)

	log.Println("Listing IAM policies...")
	// List IAM policies
	listPoliciesOutput, err := iamSvc.ListPolicies(ctx, &iam.ListPoliciesInput{})
	if err != nil {
		return fmt.Errorf("failed to list IAM policies: %v", err)
	}
	log.Printf("Found %d IAM policies.\n", len(listPoliciesOutput.Policies))

	for _, policy := range listPoliciesOutput.Policies {
		log.Printf("Checking IAM policy: %s\n", *policy.PolicyName)

		// Retrieve the default policy version for this policy
		policyVersionOutput, err := iamSvc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policy.Arn,
			VersionId: policy.DefaultVersionId,
		})
		if err != nil {
			return fmt.Errorf("failed to get IAM policy version for %s: %v", *policy.PolicyName, err)
		}

		// Decode the policy document, which is URL-encoded
		policyDocument := *policyVersionOutput.PolicyVersion.Document
		log.Printf("Decoding policy document for IAM policy: %s\n", *policy.PolicyName)
		policyDocDecoded, err := urlDecode(policyDocument)
		if err != nil {
			return fmt.Errorf("failed to decode policy document for %s: %v", *policy.PolicyName, err)
		}

		// Check for mobile code permissions
		if containsMobileCodePermissions(policyDocDecoded) {
			log.Printf("Warning: IAM Policy %s allows potential mobile code uploads.\n", *policy.PolicyName)
		}
	}

	return nil
}

// urlDecode decodes the URL-encoded policy document.
func urlDecode(encoded string) (string, error) {
	log.Println("URL-decoding policy document...")
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to URL decode policy document: %v", err)
	}
	return decoded, nil
}

// checkS3BucketsForMobileCode checks S3 buckets for mobile code and ensures access control is in place.
func checkS3BucketsForMobileCode(ctx context.Context, cfg aws.Config) error {
	s3Svc := s3.NewFromConfig(cfg)

	log.Println("Listing S3 buckets...")
	// List all S3 buckets
	result, err := s3Svc.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("unable to list S3 buckets: %v", err)
	}
	log.Printf("Found %d S3 buckets.\n", len(result.Buckets))

	for _, bucket := range result.Buckets {
		log.Printf("Checking S3 Bucket: %s for mobile code\n", *bucket.Name)

		// Simulate checking bucket content or policies for mobile code
		if containsMobileCodeInBucket(*bucket.Name) {
			return fmt.Errorf("S3 bucket %s contains mobile code. Ensure it is properly monitored and controlled.", *bucket.Name)
		}
	}

	return nil
}

// checkCloudFrontForMobileCode checks CloudFront distributions for mobile code execution.
func checkCloudFrontForMobileCode(ctx context.Context, cfg aws.Config) error {
	cloudFrontSvc := cloudfront.NewFromConfig(cfg)

	log.Println("Listing CloudFront distributions...")
	// List all CloudFront distributions
	result, err := cloudFrontSvc.ListDistributions(ctx, &cloudfront.ListDistributionsInput{})
	if err != nil {
		return fmt.Errorf("failed to list CloudFront distributions: %v", err)
	}
	log.Printf("Found %d CloudFront distributions.\n", len(result.DistributionList.Items))

	for _, distribution := range result.DistributionList.Items {
		log.Printf("Checking CloudFront Distribution: %s\n", *distribution.Id)

		// Simulate checking for mobile code served via CloudFront
		if containsMobileCodeInDistribution(*distribution.Id) {
			return fmt.Errorf("CloudFront distribution %s serves mobile code. Ensure it is properly monitored and controlled.", *distribution.Id)
		}
	}

	return nil
}

// containsMobileCodePermissions checks if an IAM policy document contains permissions related to mobile code uploads.
func containsMobileCodePermissions(policyDocument string) bool {
	log.Println("Checking IAM policy document for mobile code permissions...")
	// Simulate checking for permissions that allow uploading mobile code, e.g., S3 PutObject
	var policyMap map[string]interface{}
	if err := json.Unmarshal([]byte(policyDocument), &policyMap); err != nil {
		log.Printf("Error parsing policy document: %v\n", err)
		return false
	}

	statements, ok := policyMap["Statement"].([]interface{})
	if !ok {
		return false
	}

	for _, stmt := range statements {
		statement, ok := stmt.(map[string]interface{})
		if !ok {
			continue
		}

		actions, ok := statement["Action"].([]interface{})
		if !ok {
			continue
		}

		for _, action := range actions {
			if actionStr, ok := action.(string); ok && (strings.Contains(actionStr, "s3:PutObject") || strings.Contains(actionStr, "cloudfront:CreateDistribution")) {
				return true
			}
		}
	}
	return false
}

// containsMobileCodeInBucket simulates checking an S3 bucket for mobile code.
func containsMobileCodeInBucket(bucketName string) bool {
	log.Printf("Checking bucket %s for mobile code...\n", bucketName)
	for _, m := range config.AppConfig.AWS.Protection.MobileCodes {
		if strings.Contains(bucketName, m) {
			return true
		}
	}
	return false
}

// containsMobileCodeInDistribution simulates checking a CloudFront distribution for mobile code.
func containsMobileCodeInDistribution(distributionId string) bool {
	log.Printf("Checking CloudFront distribution %s for mobile code...\n", distributionId)
	for _, m := range config.AppConfig.AWS.Protection.CloudWatchMobileCodes {
		if strings.Contains(distributionId, m) {
			return true
		}
	}
	return false
}
