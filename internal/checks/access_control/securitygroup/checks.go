package securitygroup

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// IAMCheck è una struttura che implementa il controllo della conformità alle policy IAM
type IAMCheck struct {
	Client *iam.Client
}

// NewIAMCheck inizializza una nuova istanza di IAMCheck
func NewIAMCheck(cfg aws.Config) *IAMCheck {
	return &IAMCheck{
		Client: iam.NewFromConfig(cfg),
	}
}

// Run esegue il controllo di conformità per le policy IAM
func (c *IAMCheck) Run() error {
	// Elenca gli utenti IAM
	listUsersOutput, err := c.Client.ListUsers(context.TODO(), &iam.ListUsersInput{})
	if err != nil {
		return fmt.Errorf("impossibile elencare gli utenti IAM: %v", err)
	}

	// Itera sugli utenti e verifica le policy assegnate
	for _, user := range listUsersOutput.Users {
		fmt.Printf("Verifica dell'utente: %s\n", *user.UserName)

		// Elenca le policy assegnate all'utente
		attachedPoliciesOutput, err := c.Client.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
			UserName: user.UserName,
		})
		if err != nil {
			return fmt.Errorf("impossibile elencare le policy assegnate all'utente %s: %v", *user.UserName, err)
		}

		// Itera sulle policy e controlla la conformità
		for _, policy := range attachedPoliciesOutput.AttachedPolicies {
			fmt.Printf("L'utente %s ha la policy: %s\n", *user.UserName, *policy.PolicyName)

			// Qui aggiungi la logica per confrontare la policy con i requisiti aziendali
			if err := validatePolicy(*policy.PolicyName); err != nil {
				fmt.Printf("Policy %s non conforme per l'utente %s: %v\n", *policy.PolicyName, *user.UserName, err)
			} else {
				fmt.Printf("Policy %s conforme per l'utente %s\n", *policy.PolicyName, *user.UserName)
			}
		}
	}

	return nil
}

// validatePolicy è una funzione che confronta la policy aziendale con i criteri definiti
func validatePolicy(policyName string) error {
	// Lista delle policy aziendali consentite
	allowedPolicies := []string{"ReadOnlyPolicy", "AdminPolicy", "SelfManageCredentialsPolicy"}

	isValid := false
	for _, allowed := range allowedPolicies {
		if policyName == allowed {
			isValid = true
			break
		}
	}

	if !isValid {
		return fmt.Errorf("policy %s non consentita", policyName)
	}

	return nil
}
