package integrity

import (
	"context"
	"fmt"
	"log"

	"cloud_compliance_checker/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CheckLambdaAndS3Notifications checks the presence of the Lambda function and verifies that each S3 bucket has the appropriate notification configuration.
// 03.14.03
func CheckLambdaAndS3Notifications(cfg aws.Config) error {
	ctx := context.TODO()

	// Step 1: Get bucket names (multiple) and Lambda function name from the config
	bucketNames := config.AppConfig.AWS.Integrity.BucketNames
	lambdaFunctionName := config.AppConfig.AWS.Integrity.LambdaName

	if len(bucketNames) == 0 || lambdaFunctionName == "" {
		return fmt.Errorf("bucket names or lambda function name is not set in the configuration")
	}

	// Step 2: Check if the Lambda function exists
	err := checkLambdaExists(ctx, cfg, lambdaFunctionName)
	if err != nil {
		return fmt.Errorf("Lambda function check failed: %v", err)
	}
	log.Printf("Lambda function %s exists.\n", lambdaFunctionName)

	// Step 3: Loop through each bucket and check the notification configuration
	for _, bucketName := range bucketNames {
		err := checkS3NotificationConfiguration(ctx, cfg, bucketName, lambdaFunctionName)
		if err != nil {
			log.Printf("[ERROR]: S3 bucket %s notification configuration check failed: %v\n", bucketName, err)
		} else {
			log.Printf("S3 bucket %s has the correct notification configuration for Lambda %s.\n", bucketName, lambdaFunctionName)
		}
	}

	return nil
}

// checkLambdaExists checks if the Lambda function exists
func checkLambdaExists(ctx context.Context, cfg aws.Config, lambdaFunctionName string) error {
	lambdaClient := lambda.NewFromConfig(cfg)

	// Get Lambda function details
	_, err := lambdaClient.GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: &lambdaFunctionName,
	})
	if err != nil {
		return fmt.Errorf("Lambda function %s not found: %v", lambdaFunctionName, err)
	}

	return nil
}

// checkS3NotificationConfiguration checks if the S3 bucket has the notification configuration for the Lambda function
func checkS3NotificationConfiguration(ctx context.Context, cfg aws.Config, bucketName string, lambdaFunctionName string) error {
	s3Client := s3.NewFromConfig(cfg)

	// Get the bucket notification configuration
	result, err := s3Client.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return fmt.Errorf("unable to get notification configuration for bucket %s: %v", bucketName, err)
	}

	// Check if the Lambda function is configured as a notification destination
	for _, lambdaConfig := range result.LambdaFunctionConfigurations {
		if *lambdaConfig.LambdaFunctionArn == lambdaFunctionName {
			return nil // Found the correct Lambda configuration
		}
	}

	return fmt.Errorf("no notification configuration for Lambda function %s found in bucket %s", lambdaFunctionName, bucketName)
}
