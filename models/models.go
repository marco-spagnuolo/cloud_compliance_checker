package models

// Asset represents a cloud asset
type Asset struct {
	Name    string
	Type    string
	Cloud   string
	Details interface{}
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
	Description   string `json:"description"`
	CheckFunction string `json:"check_function"`
	Value         int    `json:"value"`
}

// Control represents a NIST control with multiple criteria
type Control struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Criteria    []Criteria `json:"criteria"`
}

// NISTControls represents a collection of NIST controls
type NISTControls struct {
	Controls []Control
}
