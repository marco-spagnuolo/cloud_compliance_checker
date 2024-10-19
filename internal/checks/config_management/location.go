package config_management

import (
	"cloud_compliance_checker/models"
	"fmt"
	"log"
	"time"
)

// CUIComponent represents AWS resources where CUI is processed or stored
type CUIComponent struct {
	ComponentName string
	InstanceID    string
	CUIType       string
	Location      string
	AccessUsers   []string
	LastModified  time.Time
}

// Global list to store AWS resources that store/process CUI
var cuiComponents []CUIComponent

// Function to document AWS resources (EC2/S3) that store/process CUI from discovered assets
func DocumentDiscoveredAssets(assets []models.Asset) {
	for _, asset := range assets {
		// Assuming all discovered assets involve CUI. Customize this logic as needed.
		cuiType := "Confidential"                 // Replace with actual CUI classification logic
		location := asset.Name                    // You may customize location extraction logic based on asset type
		accessUsers := []string{"user1", "user2"} // Replace with actual access users

		// Document each asset as a CUI component
		cuiComponent := CUIComponent{
			ComponentName: asset.Name,
			InstanceID:    asset.Name, // Reusing name as ID, customize this if needed
			CUIType:       cuiType,
			Location:      location,
			AccessUsers:   accessUsers,
			LastModified:  time.Now(),
		}

		cuiComponents = append(cuiComponents, cuiComponent)
		log.Printf("CUI Component Added: Component Name: %s, InstanceID: %s, CUI Type: %s, Location: %s\n", asset.Name, asset.Name, cuiType, location)
	}
}

// Function to display current AWS resources that store/process CUI
func DisplayCUIComponents() error {
	log.Println("Displaying CUI Components Information...")
	if len(cuiComponents) == 0 {
		errMessage := "No CUI components available to display"
		log.Println(errMessage)
		return fmt.Errorf("no CUI components available to display")
	}

	for _, component := range cuiComponents {
		log.Printf("Component: %s, Instance ID: %s, CUI Type: %s, Location: %s, Users with Access: %v, Last Modified: %s\n",
			component.ComponentName, component.InstanceID, component.CUIType, component.Location, component.AccessUsers, component.LastModified)
	}
	return nil
}
