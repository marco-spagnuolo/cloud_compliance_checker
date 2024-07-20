package incident_response

import (
	"context"
	"testing"

	"cloud_compliance_checker/models"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockInspectorAPI is a mock type for the inspectoriface.InspectorAPI
type MockInspectorAPI struct {
	mock.Mock
}

// AddAttributesToFindings implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) AddAttributesToFindings(*inspector.AddAttributesToFindingsInput) (*inspector.AddAttributesToFindingsOutput, error) {
	panic("unimplemented")
}

// AddAttributesToFindingsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) AddAttributesToFindingsRequest(*inspector.AddAttributesToFindingsInput) (*request.Request, *inspector.AddAttributesToFindingsOutput) {
	panic("unimplemented")
}

// AddAttributesToFindingsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) AddAttributesToFindingsWithContext(context.Context, *inspector.AddAttributesToFindingsInput, ...request.Option) (*inspector.AddAttributesToFindingsOutput, error) {
	panic("unimplemented")
}

// CreateAssessmentTarget implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateAssessmentTarget(*inspector.CreateAssessmentTargetInput) (*inspector.CreateAssessmentTargetOutput, error) {
	panic("unimplemented")
}

// CreateAssessmentTargetRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateAssessmentTargetRequest(*inspector.CreateAssessmentTargetInput) (*request.Request, *inspector.CreateAssessmentTargetOutput) {
	panic("unimplemented")
}

// CreateAssessmentTargetWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateAssessmentTargetWithContext(context.Context, *inspector.CreateAssessmentTargetInput, ...request.Option) (*inspector.CreateAssessmentTargetOutput, error) {
	panic("unimplemented")
}

// CreateAssessmentTemplate implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateAssessmentTemplate(*inspector.CreateAssessmentTemplateInput) (*inspector.CreateAssessmentTemplateOutput, error) {
	panic("unimplemented")
}

// CreateAssessmentTemplateRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateAssessmentTemplateRequest(*inspector.CreateAssessmentTemplateInput) (*request.Request, *inspector.CreateAssessmentTemplateOutput) {
	panic("unimplemented")
}

// CreateAssessmentTemplateWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateAssessmentTemplateWithContext(context.Context, *inspector.CreateAssessmentTemplateInput, ...request.Option) (*inspector.CreateAssessmentTemplateOutput, error) {
	panic("unimplemented")
}

// CreateExclusionsPreview implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateExclusionsPreview(*inspector.CreateExclusionsPreviewInput) (*inspector.CreateExclusionsPreviewOutput, error) {
	panic("unimplemented")
}

// CreateExclusionsPreviewRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateExclusionsPreviewRequest(*inspector.CreateExclusionsPreviewInput) (*request.Request, *inspector.CreateExclusionsPreviewOutput) {
	panic("unimplemented")
}

// CreateExclusionsPreviewWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateExclusionsPreviewWithContext(context.Context, *inspector.CreateExclusionsPreviewInput, ...request.Option) (*inspector.CreateExclusionsPreviewOutput, error) {
	panic("unimplemented")
}

// CreateResourceGroup implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateResourceGroup(*inspector.CreateResourceGroupInput) (*inspector.CreateResourceGroupOutput, error) {
	panic("unimplemented")
}

// CreateResourceGroupRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateResourceGroupRequest(*inspector.CreateResourceGroupInput) (*request.Request, *inspector.CreateResourceGroupOutput) {
	panic("unimplemented")
}

// CreateResourceGroupWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) CreateResourceGroupWithContext(context.Context, *inspector.CreateResourceGroupInput, ...request.Option) (*inspector.CreateResourceGroupOutput, error) {
	panic("unimplemented")
}

// DeleteAssessmentRun implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentRun(*inspector.DeleteAssessmentRunInput) (*inspector.DeleteAssessmentRunOutput, error) {
	panic("unimplemented")
}

// DeleteAssessmentRunRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentRunRequest(*inspector.DeleteAssessmentRunInput) (*request.Request, *inspector.DeleteAssessmentRunOutput) {
	panic("unimplemented")
}

// DeleteAssessmentRunWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentRunWithContext(context.Context, *inspector.DeleteAssessmentRunInput, ...request.Option) (*inspector.DeleteAssessmentRunOutput, error) {
	panic("unimplemented")
}

// DeleteAssessmentTarget implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentTarget(*inspector.DeleteAssessmentTargetInput) (*inspector.DeleteAssessmentTargetOutput, error) {
	panic("unimplemented")
}

// DeleteAssessmentTargetRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentTargetRequest(*inspector.DeleteAssessmentTargetInput) (*request.Request, *inspector.DeleteAssessmentTargetOutput) {
	panic("unimplemented")
}

// DeleteAssessmentTargetWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentTargetWithContext(context.Context, *inspector.DeleteAssessmentTargetInput, ...request.Option) (*inspector.DeleteAssessmentTargetOutput, error) {
	panic("unimplemented")
}

// DeleteAssessmentTemplate implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentTemplate(*inspector.DeleteAssessmentTemplateInput) (*inspector.DeleteAssessmentTemplateOutput, error) {
	panic("unimplemented")
}

// DeleteAssessmentTemplateRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentTemplateRequest(*inspector.DeleteAssessmentTemplateInput) (*request.Request, *inspector.DeleteAssessmentTemplateOutput) {
	panic("unimplemented")
}

// DeleteAssessmentTemplateWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DeleteAssessmentTemplateWithContext(context.Context, *inspector.DeleteAssessmentTemplateInput, ...request.Option) (*inspector.DeleteAssessmentTemplateOutput, error) {
	panic("unimplemented")
}

// DescribeAssessmentRuns implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentRuns(*inspector.DescribeAssessmentRunsInput) (*inspector.DescribeAssessmentRunsOutput, error) {
	panic("unimplemented")
}

// DescribeAssessmentRunsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentRunsRequest(*inspector.DescribeAssessmentRunsInput) (*request.Request, *inspector.DescribeAssessmentRunsOutput) {
	panic("unimplemented")
}

// DescribeAssessmentRunsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentRunsWithContext(context.Context, *inspector.DescribeAssessmentRunsInput, ...request.Option) (*inspector.DescribeAssessmentRunsOutput, error) {
	panic("unimplemented")
}

// DescribeAssessmentTargets implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentTargets(*inspector.DescribeAssessmentTargetsInput) (*inspector.DescribeAssessmentTargetsOutput, error) {
	panic("unimplemented")
}

// DescribeAssessmentTargetsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentTargetsRequest(*inspector.DescribeAssessmentTargetsInput) (*request.Request, *inspector.DescribeAssessmentTargetsOutput) {
	panic("unimplemented")
}

// DescribeAssessmentTargetsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentTargetsWithContext(context.Context, *inspector.DescribeAssessmentTargetsInput, ...request.Option) (*inspector.DescribeAssessmentTargetsOutput, error) {
	panic("unimplemented")
}

// DescribeAssessmentTemplates implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentTemplates(*inspector.DescribeAssessmentTemplatesInput) (*inspector.DescribeAssessmentTemplatesOutput, error) {
	panic("unimplemented")
}

// DescribeAssessmentTemplatesRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentTemplatesRequest(*inspector.DescribeAssessmentTemplatesInput) (*request.Request, *inspector.DescribeAssessmentTemplatesOutput) {
	panic("unimplemented")
}

// DescribeAssessmentTemplatesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeAssessmentTemplatesWithContext(context.Context, *inspector.DescribeAssessmentTemplatesInput, ...request.Option) (*inspector.DescribeAssessmentTemplatesOutput, error) {
	panic("unimplemented")
}

// DescribeCrossAccountAccessRole implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeCrossAccountAccessRole(*inspector.DescribeCrossAccountAccessRoleInput) (*inspector.DescribeCrossAccountAccessRoleOutput, error) {
	panic("unimplemented")
}

// DescribeCrossAccountAccessRoleRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeCrossAccountAccessRoleRequest(*inspector.DescribeCrossAccountAccessRoleInput) (*request.Request, *inspector.DescribeCrossAccountAccessRoleOutput) {
	panic("unimplemented")
}

// DescribeCrossAccountAccessRoleWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeCrossAccountAccessRoleWithContext(context.Context, *inspector.DescribeCrossAccountAccessRoleInput, ...request.Option) (*inspector.DescribeCrossAccountAccessRoleOutput, error) {
	panic("unimplemented")
}

// DescribeExclusions implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeExclusions(*inspector.DescribeExclusionsInput) (*inspector.DescribeExclusionsOutput, error) {
	panic("unimplemented")
}

// DescribeExclusionsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeExclusionsRequest(*inspector.DescribeExclusionsInput) (*request.Request, *inspector.DescribeExclusionsOutput) {
	panic("unimplemented")
}

// DescribeExclusionsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeExclusionsWithContext(context.Context, *inspector.DescribeExclusionsInput, ...request.Option) (*inspector.DescribeExclusionsOutput, error) {
	panic("unimplemented")
}

// DescribeFindings implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeFindings(*inspector.DescribeFindingsInput) (*inspector.DescribeFindingsOutput, error) {
	panic("unimplemented")
}

// DescribeFindingsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeFindingsRequest(*inspector.DescribeFindingsInput) (*request.Request, *inspector.DescribeFindingsOutput) {
	panic("unimplemented")
}

// DescribeFindingsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeFindingsWithContext(context.Context, *inspector.DescribeFindingsInput, ...request.Option) (*inspector.DescribeFindingsOutput, error) {
	panic("unimplemented")
}

// DescribeResourceGroups implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeResourceGroups(*inspector.DescribeResourceGroupsInput) (*inspector.DescribeResourceGroupsOutput, error) {
	panic("unimplemented")
}

// DescribeResourceGroupsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeResourceGroupsRequest(*inspector.DescribeResourceGroupsInput) (*request.Request, *inspector.DescribeResourceGroupsOutput) {
	panic("unimplemented")
}

// DescribeResourceGroupsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeResourceGroupsWithContext(context.Context, *inspector.DescribeResourceGroupsInput, ...request.Option) (*inspector.DescribeResourceGroupsOutput, error) {
	panic("unimplemented")
}

// DescribeRulesPackages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeRulesPackages(*inspector.DescribeRulesPackagesInput) (*inspector.DescribeRulesPackagesOutput, error) {
	panic("unimplemented")
}

// DescribeRulesPackagesRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeRulesPackagesRequest(*inspector.DescribeRulesPackagesInput) (*request.Request, *inspector.DescribeRulesPackagesOutput) {
	panic("unimplemented")
}

// DescribeRulesPackagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) DescribeRulesPackagesWithContext(context.Context, *inspector.DescribeRulesPackagesInput, ...request.Option) (*inspector.DescribeRulesPackagesOutput, error) {
	panic("unimplemented")
}

// GetAssessmentReport implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetAssessmentReport(*inspector.GetAssessmentReportInput) (*inspector.GetAssessmentReportOutput, error) {
	panic("unimplemented")
}

// GetAssessmentReportRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetAssessmentReportRequest(*inspector.GetAssessmentReportInput) (*request.Request, *inspector.GetAssessmentReportOutput) {
	panic("unimplemented")
}

// GetAssessmentReportWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetAssessmentReportWithContext(context.Context, *inspector.GetAssessmentReportInput, ...request.Option) (*inspector.GetAssessmentReportOutput, error) {
	panic("unimplemented")
}

// GetExclusionsPreview implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetExclusionsPreview(*inspector.GetExclusionsPreviewInput) (*inspector.GetExclusionsPreviewOutput, error) {
	panic("unimplemented")
}

// GetExclusionsPreviewPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetExclusionsPreviewPages(*inspector.GetExclusionsPreviewInput, func(*inspector.GetExclusionsPreviewOutput, bool) bool) error {
	panic("unimplemented")
}

// GetExclusionsPreviewPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetExclusionsPreviewPagesWithContext(context.Context, *inspector.GetExclusionsPreviewInput, func(*inspector.GetExclusionsPreviewOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// GetExclusionsPreviewRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetExclusionsPreviewRequest(*inspector.GetExclusionsPreviewInput) (*request.Request, *inspector.GetExclusionsPreviewOutput) {
	panic("unimplemented")
}

// GetExclusionsPreviewWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetExclusionsPreviewWithContext(context.Context, *inspector.GetExclusionsPreviewInput, ...request.Option) (*inspector.GetExclusionsPreviewOutput, error) {
	panic("unimplemented")
}

// GetTelemetryMetadata implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetTelemetryMetadata(*inspector.GetTelemetryMetadataInput) (*inspector.GetTelemetryMetadataOutput, error) {
	panic("unimplemented")
}

// GetTelemetryMetadataRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetTelemetryMetadataRequest(*inspector.GetTelemetryMetadataInput) (*request.Request, *inspector.GetTelemetryMetadataOutput) {
	panic("unimplemented")
}

// GetTelemetryMetadataWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) GetTelemetryMetadataWithContext(context.Context, *inspector.GetTelemetryMetadataInput, ...request.Option) (*inspector.GetTelemetryMetadataOutput, error) {
	panic("unimplemented")
}

// ListAssessmentRunAgents implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunAgents(*inspector.ListAssessmentRunAgentsInput) (*inspector.ListAssessmentRunAgentsOutput, error) {
	panic("unimplemented")
}

// ListAssessmentRunAgentsPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunAgentsPages(*inspector.ListAssessmentRunAgentsInput, func(*inspector.ListAssessmentRunAgentsOutput, bool) bool) error {
	panic("unimplemented")
}

// ListAssessmentRunAgentsPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunAgentsPagesWithContext(context.Context, *inspector.ListAssessmentRunAgentsInput, func(*inspector.ListAssessmentRunAgentsOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListAssessmentRunAgentsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunAgentsRequest(*inspector.ListAssessmentRunAgentsInput) (*request.Request, *inspector.ListAssessmentRunAgentsOutput) {
	panic("unimplemented")
}

// ListAssessmentRunAgentsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunAgentsWithContext(context.Context, *inspector.ListAssessmentRunAgentsInput, ...request.Option) (*inspector.ListAssessmentRunAgentsOutput, error) {
	panic("unimplemented")
}

// ListAssessmentRuns implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRuns(*inspector.ListAssessmentRunsInput) (*inspector.ListAssessmentRunsOutput, error) {
	panic("unimplemented")
}

// ListAssessmentRunsPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunsPages(*inspector.ListAssessmentRunsInput, func(*inspector.ListAssessmentRunsOutput, bool) bool) error {
	panic("unimplemented")
}

// ListAssessmentRunsPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunsPagesWithContext(context.Context, *inspector.ListAssessmentRunsInput, func(*inspector.ListAssessmentRunsOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListAssessmentRunsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunsRequest(*inspector.ListAssessmentRunsInput) (*request.Request, *inspector.ListAssessmentRunsOutput) {
	panic("unimplemented")
}

// ListAssessmentRunsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentRunsWithContext(context.Context, *inspector.ListAssessmentRunsInput, ...request.Option) (*inspector.ListAssessmentRunsOutput, error) {
	panic("unimplemented")
}

// ListAssessmentTargets implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTargets(*inspector.ListAssessmentTargetsInput) (*inspector.ListAssessmentTargetsOutput, error) {
	panic("unimplemented")
}

// ListAssessmentTargetsPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTargetsPages(*inspector.ListAssessmentTargetsInput, func(*inspector.ListAssessmentTargetsOutput, bool) bool) error {
	panic("unimplemented")
}

// ListAssessmentTargetsPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTargetsPagesWithContext(context.Context, *inspector.ListAssessmentTargetsInput, func(*inspector.ListAssessmentTargetsOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListAssessmentTargetsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTargetsRequest(*inspector.ListAssessmentTargetsInput) (*request.Request, *inspector.ListAssessmentTargetsOutput) {
	panic("unimplemented")
}

// ListAssessmentTargetsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTargetsWithContext(context.Context, *inspector.ListAssessmentTargetsInput, ...request.Option) (*inspector.ListAssessmentTargetsOutput, error) {
	panic("unimplemented")
}

// ListAssessmentTemplates implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTemplates(*inspector.ListAssessmentTemplatesInput) (*inspector.ListAssessmentTemplatesOutput, error) {
	panic("unimplemented")
}

// ListAssessmentTemplatesPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTemplatesPages(*inspector.ListAssessmentTemplatesInput, func(*inspector.ListAssessmentTemplatesOutput, bool) bool) error {
	panic("unimplemented")
}

// ListAssessmentTemplatesPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTemplatesPagesWithContext(context.Context, *inspector.ListAssessmentTemplatesInput, func(*inspector.ListAssessmentTemplatesOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListAssessmentTemplatesRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTemplatesRequest(*inspector.ListAssessmentTemplatesInput) (*request.Request, *inspector.ListAssessmentTemplatesOutput) {
	panic("unimplemented")
}

// ListAssessmentTemplatesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListAssessmentTemplatesWithContext(context.Context, *inspector.ListAssessmentTemplatesInput, ...request.Option) (*inspector.ListAssessmentTemplatesOutput, error) {
	panic("unimplemented")
}

// ListEventSubscriptions implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListEventSubscriptions(*inspector.ListEventSubscriptionsInput) (*inspector.ListEventSubscriptionsOutput, error) {
	panic("unimplemented")
}

// ListEventSubscriptionsPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListEventSubscriptionsPages(*inspector.ListEventSubscriptionsInput, func(*inspector.ListEventSubscriptionsOutput, bool) bool) error {
	panic("unimplemented")
}

// ListEventSubscriptionsPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListEventSubscriptionsPagesWithContext(context.Context, *inspector.ListEventSubscriptionsInput, func(*inspector.ListEventSubscriptionsOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListEventSubscriptionsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListEventSubscriptionsRequest(*inspector.ListEventSubscriptionsInput) (*request.Request, *inspector.ListEventSubscriptionsOutput) {
	panic("unimplemented")
}

// ListEventSubscriptionsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListEventSubscriptionsWithContext(context.Context, *inspector.ListEventSubscriptionsInput, ...request.Option) (*inspector.ListEventSubscriptionsOutput, error) {
	panic("unimplemented")
}

// ListExclusions implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListExclusions(*inspector.ListExclusionsInput) (*inspector.ListExclusionsOutput, error) {
	panic("unimplemented")
}

// ListExclusionsPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListExclusionsPages(*inspector.ListExclusionsInput, func(*inspector.ListExclusionsOutput, bool) bool) error {
	panic("unimplemented")
}

// ListExclusionsPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListExclusionsPagesWithContext(context.Context, *inspector.ListExclusionsInput, func(*inspector.ListExclusionsOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListExclusionsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListExclusionsRequest(*inspector.ListExclusionsInput) (*request.Request, *inspector.ListExclusionsOutput) {
	panic("unimplemented")
}

// ListExclusionsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListExclusionsWithContext(context.Context, *inspector.ListExclusionsInput, ...request.Option) (*inspector.ListExclusionsOutput, error) {
	panic("unimplemented")
}

// ListFindingsPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListFindingsPages(*inspector.ListFindingsInput, func(*inspector.ListFindingsOutput, bool) bool) error {
	panic("unimplemented")
}

// ListFindingsPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListFindingsPagesWithContext(context.Context, *inspector.ListFindingsInput, func(*inspector.ListFindingsOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListFindingsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListFindingsRequest(*inspector.ListFindingsInput) (*request.Request, *inspector.ListFindingsOutput) {
	panic("unimplemented")
}

// ListFindingsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListFindingsWithContext(context.Context, *inspector.ListFindingsInput, ...request.Option) (*inspector.ListFindingsOutput, error) {
	panic("unimplemented")
}

// ListRulesPackages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListRulesPackages(*inspector.ListRulesPackagesInput) (*inspector.ListRulesPackagesOutput, error) {
	panic("unimplemented")
}

// ListRulesPackagesPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListRulesPackagesPages(*inspector.ListRulesPackagesInput, func(*inspector.ListRulesPackagesOutput, bool) bool) error {
	panic("unimplemented")
}

// ListRulesPackagesPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListRulesPackagesPagesWithContext(context.Context, *inspector.ListRulesPackagesInput, func(*inspector.ListRulesPackagesOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// ListRulesPackagesRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListRulesPackagesRequest(*inspector.ListRulesPackagesInput) (*request.Request, *inspector.ListRulesPackagesOutput) {
	panic("unimplemented")
}

// ListRulesPackagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListRulesPackagesWithContext(context.Context, *inspector.ListRulesPackagesInput, ...request.Option) (*inspector.ListRulesPackagesOutput, error) {
	panic("unimplemented")
}

// ListTagsForResource implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListTagsForResource(*inspector.ListTagsForResourceInput) (*inspector.ListTagsForResourceOutput, error) {
	panic("unimplemented")
}

// ListTagsForResourceRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListTagsForResourceRequest(*inspector.ListTagsForResourceInput) (*request.Request, *inspector.ListTagsForResourceOutput) {
	panic("unimplemented")
}

// ListTagsForResourceWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) ListTagsForResourceWithContext(context.Context, *inspector.ListTagsForResourceInput, ...request.Option) (*inspector.ListTagsForResourceOutput, error) {
	panic("unimplemented")
}

// PreviewAgents implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) PreviewAgents(*inspector.PreviewAgentsInput) (*inspector.PreviewAgentsOutput, error) {
	panic("unimplemented")
}

// PreviewAgentsPages implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) PreviewAgentsPages(*inspector.PreviewAgentsInput, func(*inspector.PreviewAgentsOutput, bool) bool) error {
	panic("unimplemented")
}

// PreviewAgentsPagesWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) PreviewAgentsPagesWithContext(context.Context, *inspector.PreviewAgentsInput, func(*inspector.PreviewAgentsOutput, bool) bool, ...request.Option) error {
	panic("unimplemented")
}

// PreviewAgentsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) PreviewAgentsRequest(*inspector.PreviewAgentsInput) (*request.Request, *inspector.PreviewAgentsOutput) {
	panic("unimplemented")
}

// PreviewAgentsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) PreviewAgentsWithContext(context.Context, *inspector.PreviewAgentsInput, ...request.Option) (*inspector.PreviewAgentsOutput, error) {
	panic("unimplemented")
}

// RegisterCrossAccountAccessRole implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) RegisterCrossAccountAccessRole(*inspector.RegisterCrossAccountAccessRoleInput) (*inspector.RegisterCrossAccountAccessRoleOutput, error) {
	panic("unimplemented")
}

// RegisterCrossAccountAccessRoleRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) RegisterCrossAccountAccessRoleRequest(*inspector.RegisterCrossAccountAccessRoleInput) (*request.Request, *inspector.RegisterCrossAccountAccessRoleOutput) {
	panic("unimplemented")
}

// RegisterCrossAccountAccessRoleWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) RegisterCrossAccountAccessRoleWithContext(context.Context, *inspector.RegisterCrossAccountAccessRoleInput, ...request.Option) (*inspector.RegisterCrossAccountAccessRoleOutput, error) {
	panic("unimplemented")
}

// RemoveAttributesFromFindings implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) RemoveAttributesFromFindings(*inspector.RemoveAttributesFromFindingsInput) (*inspector.RemoveAttributesFromFindingsOutput, error) {
	panic("unimplemented")
}

// RemoveAttributesFromFindingsRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) RemoveAttributesFromFindingsRequest(*inspector.RemoveAttributesFromFindingsInput) (*request.Request, *inspector.RemoveAttributesFromFindingsOutput) {
	panic("unimplemented")
}

// RemoveAttributesFromFindingsWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) RemoveAttributesFromFindingsWithContext(context.Context, *inspector.RemoveAttributesFromFindingsInput, ...request.Option) (*inspector.RemoveAttributesFromFindingsOutput, error) {
	panic("unimplemented")
}

// SetTagsForResource implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) SetTagsForResource(*inspector.SetTagsForResourceInput) (*inspector.SetTagsForResourceOutput, error) {
	panic("unimplemented")
}

// SetTagsForResourceRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) SetTagsForResourceRequest(*inspector.SetTagsForResourceInput) (*request.Request, *inspector.SetTagsForResourceOutput) {
	panic("unimplemented")
}

// SetTagsForResourceWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) SetTagsForResourceWithContext(context.Context, *inspector.SetTagsForResourceInput, ...request.Option) (*inspector.SetTagsForResourceOutput, error) {
	panic("unimplemented")
}

// StartAssessmentRun implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) StartAssessmentRun(*inspector.StartAssessmentRunInput) (*inspector.StartAssessmentRunOutput, error) {
	panic("unimplemented")
}

// StartAssessmentRunRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) StartAssessmentRunRequest(*inspector.StartAssessmentRunInput) (*request.Request, *inspector.StartAssessmentRunOutput) {
	panic("unimplemented")
}

// StartAssessmentRunWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) StartAssessmentRunWithContext(context.Context, *inspector.StartAssessmentRunInput, ...request.Option) (*inspector.StartAssessmentRunOutput, error) {
	panic("unimplemented")
}

// StopAssessmentRun implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) StopAssessmentRun(*inspector.StopAssessmentRunInput) (*inspector.StopAssessmentRunOutput, error) {
	panic("unimplemented")
}

// StopAssessmentRunRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) StopAssessmentRunRequest(*inspector.StopAssessmentRunInput) (*request.Request, *inspector.StopAssessmentRunOutput) {
	panic("unimplemented")
}

// StopAssessmentRunWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) StopAssessmentRunWithContext(context.Context, *inspector.StopAssessmentRunInput, ...request.Option) (*inspector.StopAssessmentRunOutput, error) {
	panic("unimplemented")
}

// SubscribeToEvent implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) SubscribeToEvent(*inspector.SubscribeToEventInput) (*inspector.SubscribeToEventOutput, error) {
	panic("unimplemented")
}

// SubscribeToEventRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) SubscribeToEventRequest(*inspector.SubscribeToEventInput) (*request.Request, *inspector.SubscribeToEventOutput) {
	panic("unimplemented")
}

// SubscribeToEventWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) SubscribeToEventWithContext(context.Context, *inspector.SubscribeToEventInput, ...request.Option) (*inspector.SubscribeToEventOutput, error) {
	panic("unimplemented")
}

// UnsubscribeFromEvent implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) UnsubscribeFromEvent(*inspector.UnsubscribeFromEventInput) (*inspector.UnsubscribeFromEventOutput, error) {
	panic("unimplemented")
}

// UnsubscribeFromEventRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) UnsubscribeFromEventRequest(*inspector.UnsubscribeFromEventInput) (*request.Request, *inspector.UnsubscribeFromEventOutput) {
	panic("unimplemented")
}

// UnsubscribeFromEventWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) UnsubscribeFromEventWithContext(context.Context, *inspector.UnsubscribeFromEventInput, ...request.Option) (*inspector.UnsubscribeFromEventOutput, error) {
	panic("unimplemented")
}

// UpdateAssessmentTarget implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) UpdateAssessmentTarget(*inspector.UpdateAssessmentTargetInput) (*inspector.UpdateAssessmentTargetOutput, error) {
	panic("unimplemented")
}

// UpdateAssessmentTargetRequest implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) UpdateAssessmentTargetRequest(*inspector.UpdateAssessmentTargetInput) (*request.Request, *inspector.UpdateAssessmentTargetOutput) {
	panic("unimplemented")
}

// UpdateAssessmentTargetWithContext implements inspectoriface.InspectorAPI.
func (m *MockInspectorAPI) UpdateAssessmentTargetWithContext(context.Context, *inspector.UpdateAssessmentTargetInput, ...request.Option) (*inspector.UpdateAssessmentTargetOutput, error) {
	panic("unimplemented")
}

func (m *MockInspectorAPI) ListFindings(*inspector.ListFindingsInput) (*inspector.ListFindingsOutput, error) {
	args := m.Called()
	return args.Get(0).(*inspector.ListFindingsOutput), args.Error(1)
}

// Helper function to convert slice of string to slice of *string
func toStringPtrSlice(slice []string) []*string {
	ptrSlice := make([]*string, len(slice))
	for i, v := range slice {
		ptrSlice[i] = &v
	}
	return ptrSlice
}

// TestCheckIncidentHandlingCapability tests CheckIncidentHandlingCapability
func TestCheckIncidentHandlingCapability(t *testing.T) {
	mockSvc := new(MockInspectorAPI)
	mockSvc.On("ListFindings").Return(&inspector.ListFindingsOutput{
		FindingArns: []*string{}, // Simulate no findings
	}, nil)

	result := checkIncidentHandlingCapabilityWithService(mockSvc)
	expected := models.ComplianceResult{
		Description: "Establish an operational incident-handling capability",
		Status:      "PASS",
		Response:    "No incidents found, incident handling capability is in place",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckIncidentReporting tests CheckIncidentReporting
func TestCheckIncidentReporting(t *testing.T) {
	mockSvc := new(MockInspectorAPI)
	mockSvc.On("ListFindings").Return(&inspector.ListFindingsOutput{
		FindingArns: toStringPtrSlice([]string{"arn:aws:inspector:us-west-2:123456789012:target/0-abc123"}), // Simulate one finding
	}, nil)

	result := checkIncidentReportingWithService(mockSvc)
	expected := models.ComplianceResult{
		Description: "Track, document, and report incidents",
		Status:      "PASS",
		Response:    "Incidents identified: 1. Tracking and reporting is in place.",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}

// TestCheckIncidentResponseTesting tests CheckIncidentResponseTesting
func TestCheckIncidentResponseTesting(t *testing.T) {
	result := CheckIncidentResponseTesting(&session.Session{Config: &aws.Config{}})
	expected := models.ComplianceResult{
		Description: "Test incident response capability",
		Status:      "PASS",
		Response:    "Incident response capability has been tested",
		Impact:      0,
	}

	assert.Equal(t, expected, result)
}
