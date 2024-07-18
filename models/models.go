package models

import "github.com/aws/aws-sdk-go/service/ec2"

type Asset struct {
	Name     string
	Type     string
	Cloud    string
	Instance *ec2.Instance
}

type ComplianceResult struct {
	Description string
	Status      string
	Response    string
	Impact      int
}

type AssessmentResult struct {
	Asset         Asset
	Implemented   bool
	Planned       bool
	NotApplicable bool
}

type Score struct {
	Asset Asset
	Score int
}
