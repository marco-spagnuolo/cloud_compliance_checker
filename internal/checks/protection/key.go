package protection

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// CheckKeyManagement ensures that cryptographic keys are generated, distributed, stored, accessed, and destroyed in accordance with organization-defined requirements.
// 03.13.10
func CheckKeyManagement(cfg aws.Config) error {
	ctx := context.TODO()
	kmsSvc := kms.NewFromConfig(cfg)

	// List all KMS keys
	listKeysOutput, err := kmsSvc.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return fmt.Errorf("failed to list KMS keys: %v", err)
	}

	// Check each key for proper management practices
	for _, key := range listKeysOutput.Keys {
		if err := checkKMSKeyManagement(ctx, kmsSvc, *key.KeyId); err != nil {
			log.Printf("Warning: KMS Key %s failed key management check: %v\n", *key.KeyId, err)
		} else {
			log.Printf("KMS Key %s passed key management check.\n", *key.KeyId)
		}
	}

	return nil
}

// checkKMSKeyManagement checks if a KMS key is generated, stored, accessed, and scheduled for destruction properly.
func checkKMSKeyManagement(ctx context.Context, svc *kms.Client, keyID string) error {
	// Describe the KMS key
	keyDetails, err := svc.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return fmt.Errorf("failed to describe KMS key %s: %v", keyID, err)
	}

	// Check if the key is enabled
	if keyDetails.KeyMetadata.KeyState != "Enabled" {
		return fmt.Errorf("KMS key %s is not enabled", keyID)
	}

	// Check key policy for appropriate access control
	policy, err := svc.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      &keyID,
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return fmt.Errorf("failed to get key policy for KMS key %s: %v", keyID, err)
	}
	if !isKeyPolicySecure(*policy.Policy) {
		return fmt.Errorf("KMS key %s has an insecure policy", keyID)
	}

	// Check if the key is scheduled for deletion
	if keyDetails.KeyMetadata.DeletionDate != nil {
		log.Printf("KMS key %s is scheduled for deletion on %v\n", keyID, *keyDetails.KeyMetadata.DeletionDate)
	} else {
		log.Printf("KMS key %s is not scheduled for deletion.\n", keyID)
	}

	return nil
}

// isKeyPolicySecure checks if the KMS key policy contains insecure configurations.
func isKeyPolicySecure(policy string) bool {
	// This is a basic check for open access in the key policy (e.g., "Principal": "*")
	// For a more comprehensive check, you could parse the policy JSON and inspect specific fields.
	if strings.Contains(policy, "\"Principal\":\"*\"") {
		return false // The key policy allows open access, which is insecure
	}
	return true
}
