package system_services_acquisition

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wellarchitected"
)

// CheckWellArchitectedWorkloads verifies if any Well-Architected workloads exist and checks for security reviews.
// This check ensures that security engineering principles are being applied.
func CheckSecurityEngineeringPrinciples(cfg aws.Config) error {
	ctx := context.TODO()
	wellArchClient := wellarchitected.NewFromConfig(cfg)

	// Step 1: List Well-Architected Workloads
	log.Println("Checking for Well-Architected workloads...")
	workloads, err := wellArchClient.ListWorkloads(ctx, &wellarchitected.ListWorkloadsInput{})
	if err != nil {
		return fmt.Errorf("failed to list Well-Architected workloads: %v", err)
	}

	if len(workloads.WorkloadSummaries) == 0 {
		return fmt.Errorf("no Well-Architected workloads found")
	}

	// Step 2: Iterate through workloads and check for security principles
	for _, workload := range workloads.WorkloadSummaries {
		log.Printf("Checking Well-Architected workload: %s\n", *workload.WorkloadName)

		// Check the Well-Architected workload for security pillar review
		_, err := checkSecurityPillar(ctx, wellArchClient, *workload.WorkloadId)
		if err != nil {
			log.Printf("[ERROR]: Workload %s is missing security reviews: %v\n", *workload.WorkloadName, err)
		} else {
			log.Printf("Workload %s has applied security engineering principles.\n", *workload.WorkloadName)
		}
	}

	return nil
}

// checkSecurityPillar checks if the security pillar in the Well-Architected framework has been reviewed for the workload.
func checkSecurityPillar(ctx context.Context, client *wellarchitected.Client, workloadId string) (*wellarchitected.ListLensReviewsOutput, error) {
	// Get lens reviews for the workload
	reviews, err := client.ListLensReviews(ctx, &wellarchitected.ListLensReviewsInput{
		WorkloadId: &workloadId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list lens reviews for workload %s: %v", workloadId, err)
	}

	// Check if the Security Pillar lens has been reviewed
	for _, review := range reviews.LensReviewSummaries {
		if *review.LensAlias == "wellarchitected" || *review.LensAlias == "security" {
			return reviews, nil // Security pillar is reviewed
		}
	}

	return nil, fmt.Errorf("no security lens or Well-Architected framework review found")
}
