package models

import "github.com/aws/aws-sdk-go/service/ec2"

// Asset represents a cloud asset
type Asset struct {
	Name     string
	Type     string
	Cloud    string
	Details  interface{}
	Instance *ec2.Instance
}

// ComplianceResult represents the result of a compliance check
type ComplianceResult struct {
	Description string
	Status      string
	Response    string
	Impact      int
}

// AssessmentResult represents the result of an asset assessment
type AssessmentResult struct {
	Asset         Asset
	Implemented   bool
	Planned       bool
	NotApplicable bool
}

// Score represents the compliance score of an asset
type Score struct {
	Asset Asset
	Score int
}

// Criteria represents a compliance check criteria
type Criteria struct {
	Description   string
	CheckFunction string
	Value         int
}

// Control represents a NIST control with multiple criteria
type Control struct {
	ID          string
	Name        string
	Description string
	Criteria    Criteria
}

// NISTControls represents a collection of NIST controls
type NISTControls struct {
	Controls []Control
}
