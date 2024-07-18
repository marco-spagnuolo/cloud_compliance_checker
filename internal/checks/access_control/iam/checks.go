package iam

import (
	"cloud_compliance_checker/models"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

func CheckIAMRoles(instance *ec2.Instance) models.ComplianceResult {
	if instance.IamInstanceProfile != nil {
		return models.ComplianceResult{
			Description: "Instance has IAM roles attached",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	}
	return models.ComplianceResult{
		Description: "Instance has IAM roles attached",
		Status:      "FAIL",
		Response:    "Planned to be implemented",
		Impact:      5,
	}
}

func CheckSeparateDuties(iamClient iamiface.IAMAPI, instance *ec2.Instance) models.ComplianceResult {
	if instance.IamInstanceProfile == nil {
		return models.ComplianceResult{
			Description: "Instance has roles with separate duties",
			Status:      "FAIL",
			Response:    "No IAM instance profile attached",
			Impact:      5,
		}
	}

	iamProfileArn := instance.IamInstanceProfile.Arn
	profileName, err := getInstanceProfileName(iamProfileArn)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance has roles with separate duties",
			Status:      "FAIL",
			Response:    "Error extracting instance profile name",
			Impact:      5,
		}
	}

	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	result, err := iamClient.GetInstanceProfile(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance has roles with separate duties",
			Status:      "FAIL",
			Response:    "Error describing instance profile",
			Impact:      5,
		}
	}

	if len(result.InstanceProfile.Roles) == 0 {
		return models.ComplianceResult{
			Description: "Instance has roles with separate duties",
			Status:      "FAIL",
			Response:    "No roles associated with instance profile",
			Impact:      5,
		}
	}

	separateDuties := checkRolesForSeparateDuties(result.InstanceProfile.Roles)

	if separateDuties {
		return models.ComplianceResult{
			Description: "Instance has roles with separate duties",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance has roles with separate duties",
			Status:      "FAIL",
			Response:    "Roles do not have separate duties",
			Impact:      5,
		}
	}
}

func checkRolesForSeparateDuties(roles []*iam.Role) bool {
	return len(roles) > 1
}

func CheckLeastPrivilege(iamClient iamiface.IAMAPI, instance *ec2.Instance) models.ComplianceResult {
	if instance.IamInstanceProfile == nil {
		return models.ComplianceResult{
			Description: "Instance uses least privilege for IAM roles",
			Status:      "FAIL",
			Response:    "No IAM instance profile attached",
			Impact:      5,
		}
	}

	// Estrai l'ARN del profilo IAM
	iamProfileArn := instance.IamInstanceProfile.Arn

	// Ottieni il nome del profilo IAM dall'ARN
	profileName, err := getInstanceProfileName(iamProfileArn)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance uses least privilege for IAM roles",
			Status:      "FAIL",
			Response:    "Error extracting instance profile name",
			Impact:      5,
		}
	}

	// Descrivi il profilo IAM
	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	result, err := iamClient.GetInstanceProfile(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance uses least privilege for IAM roles",
			Status:      "FAIL",
			Response:    "Error describing instance profile",
			Impact:      5,
		}
	}

	// Verifica i ruoli associati al profilo IAM
	if len(result.InstanceProfile.Roles) == 0 {
		return models.ComplianceResult{
			Description: "Instance uses least privilege for IAM roles",
			Status:      "FAIL",
			Response:    "No roles associated with instance profile",
			Impact:      5,
		}
	}

	// Placeholder logic per verificare il principio del privilegio minimo
	leastPrivilege := checkRolesForLeastPrivilege(iamClient, result.InstanceProfile.Roles)

	if leastPrivilege {
		return models.ComplianceResult{
			Description: "Instance uses least privilege for IAM roles",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance uses least privilege for IAM roles",
			Status:      "FAIL",
			Response:    "Roles do not follow the least privilege principle",
			Impact:      5,
		}
	}
}

func checkRolesForLeastPrivilege(iamClient iamiface.IAMAPI, roles []*iam.Role) bool {
	// Placeholder logic per verificare il principio del privilegio minimo nei ruoli IAM
	// La logica effettiva dovrebbe controllare i permessi dei ruoli per garantire il privilegio minimo

	for _, role := range roles {
		input := &iam.GetRolePolicyInput{
			RoleName:   aws.String(*role.RoleName),
			PolicyName: aws.String("PolicyName"), // Specifica il nome della policy da controllare
		}

		result, err := iamClient.GetRolePolicy(input)
		if err != nil {
			fmt.Printf("Error getting role policy: %v\n", err)
			return false
		}

		// Placeholder per analizzare la policy e verificare i permessi
		if !analyzePolicyForLeastPrivilege(result.PolicyDocument) {
			return false
		}
	}

	return true
}

func analyzePolicyForLeastPrivilege(policyDocument *string) bool {
	// Placeholder logic per analizzare la policy e verificare i permessi
	// La logica effettiva dovrebbe parsare il documento della policy e controllare i permessi

	// Esempio di controllo semplice: verifica che la policy non contenga permessi wildcard (*)
	return !strings.Contains(*policyDocument, "*")
}

func CheckNonPrivilegedAccounts(iamClient iamiface.IAMAPI, instance *ec2.Instance) models.ComplianceResult {
	if instance.IamInstanceProfile == nil {
		return models.ComplianceResult{
			Description: "Instance uses non-privileged roles for nonsecurity functions",
			Status:      "FAIL",
			Response:    "No IAM instance profile attached",
			Impact:      5,
		}
	}

	// Estrai l'ARN del profilo IAM
	iamProfileArn := instance.IamInstanceProfile.Arn

	// Ottieni il nome del profilo IAM dall'ARN
	profileName, err := getInstanceProfileName(iamProfileArn)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance uses non-privileged roles for nonsecurity functions",
			Status:      "FAIL",
			Response:    "Error extracting instance profile name",
			Impact:      5,
		}
	}

	// Descrivi il profilo IAM
	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	result, err := iamClient.GetInstanceProfile(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance uses non-privileged roles for nonsecurity functions",
			Status:      "FAIL",
			Response:    "Error describing instance profile",
			Impact:      5,
		}
	}

	// Verifica i ruoli associati al profilo IAM
	if len(result.InstanceProfile.Roles) == 0 {
		return models.ComplianceResult{
			Description: "Instance uses non-privileged roles for nonsecurity functions",
			Status:      "FAIL",
			Response:    "No roles associated with instance profile",
			Impact:      5,
		}
	}

	// Placeholder logic per verificare che i ruoli siano non privilegiati per funzioni non di sicurezza
	nonPrivileged := checkRolesForNonPrivileged(iamClient, result.InstanceProfile.Roles)

	if nonPrivileged {
		return models.ComplianceResult{
			Description: "Instance uses non-privileged roles for nonsecurity functions",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance uses non-privileged roles for nonsecurity functions",
			Status:      "FAIL",
			Response:    "Roles have elevated privileges",
			Impact:      5,
		}
	}
}

func checkRolesForNonPrivileged(iamClient iamiface.IAMAPI, roles []*iam.Role) bool {
	// Placeholder logic per verificare che i ruoli siano non privilegiati
	// La logica effettiva dovrebbe controllare i permessi dei ruoli per garantire che non abbiano accessi elevati

	for _, role := range roles {
		input := &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		}

		result, err := iamClient.ListAttachedRolePolicies(input)
		if err != nil {
			fmt.Printf("Error listing role policies: %v\n", err)
			return false
		}

		for _, policy := range result.AttachedPolicies {
			policyInput := &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			}
			policyResult, err := iamClient.GetPolicy(policyInput)
			if err != nil {
				fmt.Printf("Error getting policy: %v\n", err)
				return false
			}

			policyVersionInput := &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: policyResult.Policy.DefaultVersionId,
			}
			policyVersionResult, err := iamClient.GetPolicyVersion(policyVersionInput)
			if err != nil {
				fmt.Printf("Error getting policy version: %v\n", err)
				return false
			}

			// Placeholder per analizzare la policy e verificare i permessi
			if !analyzePolicyForNonPrivileged(policyVersionResult.PolicyVersion.Document) {
				return false
			}
		}
	}

	return true
}

func analyzePolicyForNonPrivileged(policyDocument *string) bool {
	// Placeholder logic per analizzare la policy e verificare i permessi
	// La logica effettiva dovrebbe parsare il documento della policy e controllare i permessi

	// Esempio di controllo semplice: verifica che la policy non contenga permessi elevati come "*"
	return !strings.Contains(*policyDocument, "*")
}

func CheckPreventPrivilegedFunctions(iamClient iamiface.IAMAPI, instance *ec2.Instance) models.ComplianceResult {
	if instance.IamInstanceProfile == nil {
		return models.ComplianceResult{
			Description: "Instance prevents non-privileged users from executing privileged functions",
			Status:      "FAIL",
			Response:    "No IAM instance profile attached",
			Impact:      5,
		}
	}

	// Estrai l'ARN del profilo IAM
	iamProfileArn := instance.IamInstanceProfile.Arn

	// Ottieni il nome del profilo IAM dall'ARN
	profileName, err := getInstanceProfileName(iamProfileArn)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance prevents non-privileged users from executing privileged functions",
			Status:      "FAIL",
			Response:    "Error extracting instance profile name",
			Impact:      5,
		}
	}

	// Descrivi il profilo IAM
	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	result, err := iamClient.GetInstanceProfile(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance prevents non-privileged users from executing privileged functions",
			Status:      "FAIL",
			Response:    "Error describing instance profile",
			Impact:      5,
		}
	}

	// Verifica i ruoli associati al profilo IAM
	if len(result.InstanceProfile.Roles) == 0 {
		return models.ComplianceResult{
			Description: "Instance prevents non-privileged users from executing privileged functions",
			Status:      "FAIL",
			Response:    "No roles associated with instance profile",
			Impact:      5,
		}
	}

	// Placeholder logic per verificare che i ruoli non abbiano permessi privilegiati
	preventsPrivilegedFunctions := checkRolesForPrivilegedFunctions(iamClient, result.InstanceProfile.Roles)

	if preventsPrivilegedFunctions {
		return models.ComplianceResult{
			Description: "Instance prevents non-privileged users from executing privileged functions",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance prevents non-privileged users from executing privileged functions",
			Status:      "FAIL",
			Response:    "Roles have privileged permissions",
			Impact:      5,
		}
	}
}

func checkRolesForPrivilegedFunctions(iamClient iamiface.IAMAPI, roles []*iam.Role) bool {
	// Placeholder logic per verificare che i ruoli non abbiano permessi privilegiati
	// La logica effettiva dovrebbe controllare i permessi dei ruoli per garantire che non abbiano accessi elevati

	for _, role := range roles {
		input := &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		}

		result, err := iamClient.ListAttachedRolePolicies(input)
		if err != nil {
			fmt.Printf("Error listing role policies: %v\n", err)
			return false
		}

		for _, policy := range result.AttachedPolicies {
			policyInput := &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			}
			policyResult, err := iamClient.GetPolicy(policyInput)
			if err != nil {
				fmt.Printf("Error getting policy: %v\n", err)
				return false
			}

			policyVersionInput := &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: policyResult.Policy.DefaultVersionId,
			}
			policyVersionResult, err := iamClient.GetPolicyVersion(policyVersionInput)
			if err != nil {
				fmt.Printf("Error getting policy version: %v\n", err)
				return false
			}

			// Placeholder per analizzare la policy e verificare i permessi
			if !analyzePolicyForPrivilegedFunctions(policyVersionResult.PolicyVersion.Document) {
				return false
			}
		}
	}

	return true
}

func analyzePolicyForPrivilegedFunctions(policyDocument *string) bool {
	// Placeholder logic per analizzare la policy e verificare i permessi
	// La logica effettiva dovrebbe parsare il documento della policy e controllare i permessi

	// Esempio di controllo semplice: verifica che la policy non contenga permessi elevati come "*"
	return !strings.Contains(*policyDocument, "*")

}

func CheckRemoteExecutionAuthorization(iamClient iamiface.IAMAPI, instance *ec2.Instance) models.ComplianceResult {
	if instance.IamInstanceProfile == nil {
		return models.ComplianceResult{
			Description: "Instance authorizes remote execution of privileged commands",
			Status:      "FAIL",
			Response:    "No IAM instance profile attached",
			Impact:      5,
		}
	}

	// Estrai l'ARN del profilo IAM
	iamProfileArn := instance.IamInstanceProfile.Arn

	// Ottieni il nome del profilo IAM dall'ARN
	profileName, err := getInstanceProfileName(iamProfileArn)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance authorizes remote execution of privileged commands",
			Status:      "FAIL",
			Response:    "Error extracting instance profile name",
			Impact:      5,
		}
	}

	// Descrivi il profilo IAM
	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	}
	result, err := iamClient.GetInstanceProfile(input)
	if err != nil {
		return models.ComplianceResult{
			Description: "Instance authorizes remote execution of privileged commands",
			Status:      "FAIL",
			Response:    fmt.Sprintf("Error describing instance profile: %v", err),
			Impact:      5,
		}
	}

	// Verifica i ruoli associati al profilo IAM
	if len(result.InstanceProfile.Roles) == 0 {
		return models.ComplianceResult{
			Description: "Instance authorizes remote execution of privileged commands",
			Status:      "FAIL",
			Response:    "No roles associated with instance profile",
			Impact:      5,
		}
	}

	// Placeholder logic per verificare che i ruoli abbiano autorizzazioni adeguate
	authorized := checkRolesForRemoteExecutionAuthorization(iamClient, result.InstanceProfile.Roles)

	if authorized {
		return models.ComplianceResult{
			Description: "Instance authorizes remote execution of privileged commands",
			Status:      "PASS",
			Response:    "Implemented",
			Impact:      0,
		}
	} else {
		return models.ComplianceResult{
			Description: "Instance authorizes remote execution of privileged commands",
			Status:      "FAIL",
			Response:    "Roles do not have appropriate authorization for remote execution",
			Impact:      5,
		}
	}
}

func getInstanceProfileName(iamProfileArn *string) (string, error) {
	// Estrai il nome del profilo IAM dall'ARN
	// Example ARN: arn:aws:iam::123456789012:instance-profile/ExampleInstanceProfile
	arnParts := strings.Split(*iamProfileArn, "/")
	if len(arnParts) < 2 {
		return "", fmt.Errorf("invalid IAM profile ARN")
	}
	return arnParts[1], nil
}

func checkRolesForRemoteExecutionAuthorization(iamClient iamiface.IAMAPI, roles []*iam.Role) bool {
	// Placeholder logic per verificare che i ruoli abbiano autorizzazioni adeguate
	// La logica effettiva dovrebbe controllare i permessi dei ruoli per garantire che abbiano autorizzazioni appropriate per l'esecuzione remota di comandi privilegiati

	for _, role := range roles {
		input := &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		}

		result, err := iamClient.ListAttachedRolePolicies(input)
		if err != nil {
			fmt.Printf("Error listing role policies: %v\n", err)
			return false
		}

		for _, policy := range result.AttachedPolicies {
			policyInput := &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			}
			policyResult, err := iamClient.GetPolicy(policyInput)
			if err != nil {
				fmt.Printf("Error getting policy: %v\n", err)
				return false
			}

			policyVersionInput := &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: policyResult.Policy.DefaultVersionId,
			}
			policyVersionResult, err := iamClient.GetPolicyVersion(policyVersionInput)
			if err != nil {
				fmt.Printf("Error getting policy version: %v\n", err)
				return false
			}

			// Placeholder per analizzare la policy e verificare i permessi
			if analyzePolicyForRemoteExecution(policyVersionResult.PolicyVersion.Document) {
				return true
			}
		}
	}

	return false
}

func analyzePolicyForRemoteExecution(policyDocument *string) bool {
	// Placeholder logic per analizzare la policy e verificare i permessi
	// La logica effettiva dovrebbe parsare il documento della policy e controllare i permessi
	// Esempio di controllo semplice: verifica che la policy contenga permessi specifici per l'esecuzione remota

	// Esempio di verifica: controlla se la policy consente l'azione "ssm:SendCommand"
	return strings.Contains(*policyDocument, "ssm:SendCommand")

}
