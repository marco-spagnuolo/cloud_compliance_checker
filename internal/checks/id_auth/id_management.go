package id_auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"cloud_compliance_checker/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// aws iam tag-user --user-name "SelfManagedUser" --tags Key=CreatorRole,Value=SelfManagedRole
// Convert custom duration format like "365d" into a valid duration string that Go can parse.
func convertToDuration(durationStr string) (time.Duration, error) {
	if strings.HasSuffix(durationStr, "d") {
		daysStr := strings.TrimSuffix(durationStr, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration format: %v", err)
		}
		// Convert days to hours
		hours := time.Duration(days*24) * time.Hour
		return hours, nil
	}
	// Use time.ParseDuration for other formats like "h", "m", etc.
	return time.ParseDuration(durationStr)
}

// Function to check if a role is authorized to assign an identifier
func isAuthorized(role string, authorizedRoles []string) bool {
	for _, authorizedRole := range authorizedRoles {
		if role == authorizedRole {
			return true
		}
	}
	return false
}

// Function to check if an identifier is reusable based on the defined period
func isIdentifierReusable(createDate time.Time, reusePreventionPeriod string) (bool, error) {
	if reusePreventionPeriod == "" {
		return false, errors.New("reuse prevention period is missing")
	}

	duration, err := convertToDuration(reusePreventionPeriod)
	if err != nil {
		return false, fmt.Errorf("invalid reuse prevention period: %v", err)
	}

	if time.Since(createDate) < duration {
		return false, nil
	}
	return true, nil
}

// Function to check if a user's status matches the required status
func checkIdentifierStatus(user *types.User, requiredStatus string) error {
	for _, tag := range user.Tags {
		if aws.ToString(tag.Key) == "Status" && aws.ToString(tag.Value) != requiredStatus {
			return fmt.Errorf("user %s has status %s, expected %s", aws.ToString(user.UserName), aws.ToString(tag.Value), requiredStatus)
		}
	}
	return nil
}

// Main function to perform the IAM checks and return errors for non-compliant users
func CheckIAM(cfg aws.Config) error {

	iamClient := iam.NewFromConfig(cfg)

	// Get the IAM users from AWS
	listUsersInput := &iam.ListUsersInput{}
	result, err := iamClient.ListUsers(context.TODO(), listUsersInput)
	if err != nil {
		log.Fatalf("Failed to list IAM users: %v", err)
		return err
	}

	// Variable to store errors for non-compliant users
	var errorMessages []string

	// Check that authorized roles are properly loaded
	log.Printf("Authorized Roles: %v\n", config.AppConfig.AWS.IdentifierManagement.AuthorizedRoles)
	log.Printf("Reuse Prevention Period: %s\n", config.AppConfig.AWS.IdentifierManagement.ReusePreventionPeriod)

	// Loop through the IAM users and perform the necessary checks
	for _, user := range result.Users {
		log.Printf("\n\n--- Checking user: %s ---\n", aws.ToString(user.UserName))

		// 1. Check if the role assigning this identifier is authorized
		log.Printf("Checking if the user %s was created by an authorized role...\n", aws.ToString(user.UserName))
		isAuthorizedRole := false
		creatorRoleTagPresent := false
		for _, tag := range user.Tags {
			if aws.ToString(tag.Key) == "CreatorRole" {
				creatorRoleTagPresent = true
				log.Printf("CreatorRole for user %s is %s\n", aws.ToString(user.UserName), aws.ToString(tag.Value))
				if isAuthorized(aws.ToString(tag.Value), config.AppConfig.AWS.IdentifierManagement.AuthorizedRoles) {
					isAuthorizedRole = true
					log.Printf("User %s was created by an authorized role.\n", aws.ToString(user.UserName))
				}
			}
		}
		if !creatorRoleTagPresent {
			log.Printf("WARNING: User %s does not have a CreatorRole tag.\n", aws.ToString(user.UserName))
		}
		if !isAuthorizedRole && creatorRoleTagPresent {
			errorMessage := fmt.Sprintf("ERROR: User %s was not created by an authorized role.", aws.ToString(user.UserName))
			errorMessages = append(errorMessages, errorMessage)
			log.Println(errorMessage)
			continue
		}

		// 2. Check identifier reuse based on the user's creation date
		if user.CreateDate == nil {
			log.Printf("ERROR: User %s does not have a valid creation date.\n", aws.ToString(user.UserName))
			continue
		}
		log.Printf("Checking if the identifier for user %s is reusable...\n", aws.ToString(user.UserName))
		reusable, err := isIdentifierReusable(*user.CreateDate, config.AppConfig.AWS.IdentifierManagement.ReusePreventionPeriod)
		if err != nil {
			errorMessage := fmt.Sprintf("ERROR: Error checking identifier reuse for user %s: %v", aws.ToString(user.UserName), err)
			errorMessages = append(errorMessages, errorMessage)
			log.Println(errorMessage)
			continue
		}
		if !reusable {
			errorMessage := fmt.Sprintf("ERROR: Identifier for user %s cannot be reused yet.", aws.ToString(user.UserName))
			errorMessages = append(errorMessages, errorMessage)
			log.Println(errorMessage)
			continue
		}
		log.Printf("Identifier for user %s is reusable.\n", aws.ToString(user.UserName))

		// 3. Check if the user has the correct status (active/inactive)
		log.Printf("Checking status for user %s...\n", aws.ToString(user.UserName))
		err = checkIdentifierStatus(&user, config.AppConfig.AWS.IdentifierManagement.IdentifierCharacteristics)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			log.Println(err.Error())
			continue
		}
		log.Printf("User %s has the correct status.\n", aws.ToString(user.UserName))

		log.Printf("--- Completed checks for user: %s ---\n", aws.ToString(user.UserName))
	}

	// If there are any error messages, return them as a single error
	if len(errorMessages) > 0 {
		log.Printf("Found non-compliant users: \n%s\n", strings.Join(errorMessages, "\n"))
		return fmt.Errorf("non-compliant users found:\n%s", strings.Join(errorMessages, "\n"))
	}

	return nil
}
