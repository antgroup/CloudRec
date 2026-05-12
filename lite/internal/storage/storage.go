package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/model"
)

type Store interface {
	Init(context.Context) error
	Close() error

	UpsertAccount(context.Context, model.Account) (model.Account, error)
	CreateScanRun(context.Context, model.ScanRun) (model.ScanRun, error)
	FinishScanRun(context.Context, string, string, json.RawMessage) (model.ScanRun, error)
	ListScanRuns(context.Context, ScanRunFilter) ([]model.ScanRun, error)
	ListScanRunsWithTotal(context.Context, ScanRunFilter) (model.ScanRunList, error)
	CountScanRuns(context.Context, ScanRunFilter) (int, error)
	InsertScanTaskRun(context.Context, model.ScanTaskRun) (model.ScanTaskRun, error)
	InsertScanTaskRuns(context.Context, []model.ScanTaskRun) error
	ListScanTaskRuns(context.Context, ScanTaskRunFilter) ([]model.ScanTaskRun, error)
	ListActiveCollectorSkipEntries(context.Context, string, string, time.Time) ([]model.CollectorSkipEntry, error)
	UpsertCollectorSkipEntry(context.Context, model.CollectorSkipEntry) (model.CollectorSkipEntry, error)
	UpsertCollectorSkipEntries(context.Context, []model.CollectorSkipEntry) error
	UpsertAsset(context.Context, model.Asset) (model.Asset, error)
	ListAssets(context.Context, AssetFilter) ([]model.Asset, error)
	ListAssetsWithTotal(context.Context, AssetFilter) (model.AssetList, error)
	ListAssetViews(context.Context, AssetFilter) (model.AssetViewList, error)
	GetAsset(context.Context, string) (model.AssetView, error)
	GetAssetView(context.Context, string) (model.AssetView, error)
	CountAssets(context.Context, AssetFilter) (int, error)
	UpsertAssetRelationship(context.Context, model.AssetRelationship) (model.AssetRelationship, error)
	ListAssetRelationships(context.Context, RelationshipFilter) ([]model.AssetRelationship, error)
	ListAssetRelationshipsWithTotal(context.Context, RelationshipFilter) (model.AssetRelationshipList, error)
	CountAssetRelationships(context.Context, RelationshipFilter) (int, error)
	UpsertAssetScanState(context.Context, model.AssetScanState) (model.AssetScanState, error)
	UpsertFinding(context.Context, model.Finding) (model.Finding, error)
	ListFindings(context.Context, FindingFilter) ([]model.Finding, error)
	ListFindingsWithTotal(context.Context, FindingFilter) (model.FindingList, error)
	ListFindingViews(context.Context, FindingFilter) (model.FindingViewList, error)
	GetFinding(context.Context, string) (model.FindingView, error)
	GetFindingView(context.Context, string) (model.FindingView, error)
	CountFindings(context.Context, FindingFilter) (int, error)
	GetSummary(context.Context, SummaryFilter) (model.Summary, error)
	GetDashboard(context.Context, DashboardFilter) (model.Dashboard, error)
	GetFacets(context.Context, FacetFilter) (model.FacetSet, error)
	GetGraph(context.Context, GraphFilter) (model.GraphResponse, error)
	ListRules(context.Context, RuleFilter) (model.RuleList, error)
	GetRule(context.Context, string) (model.RuleView, error)
}

type AssetFilter struct {
	AccountID    string
	Provider     string
	ResourceType string
	ResourceID   string
	Region       string
	Q            string
	Sort         string
	Limit        int
	Offset       int
}

type RelationshipFilter struct {
	AccountID        string
	Provider         string
	SourceAssetID    string
	SourceResourceID string
	TargetResourceID string
	ResourceType     string
	RelationshipType string
	Region           string
	Q                string
	Sort             string
	Limit            int
	Offset           int
}

type ScanRunFilter struct {
	AccountID string
	Provider  string
	Status    string
	Q         string
	Sort      string
	Limit     int
	Offset    int
}

type ScanTaskRunFilter struct {
	ScanRunID    string
	AccountID    string
	Provider     string
	ResourceType string
	Region       string
	Status       string
	Category     string
	Q            string
	Sort         string
	Limit        int
	Offset       int
}

type FindingFilter struct {
	AccountID    string
	Provider     string
	ScanRunID    string
	AssetID      string
	ResourceType string
	Region       string
	RuleID       string
	Severity     string
	Status       string
	Q            string
	Sort         string
	Limit        int
	Offset       int
}

type SummaryFilter struct {
	AccountID string
}

type DashboardFilter struct {
	AccountID string
	Provider  string
	Region    string
}

type FacetFilter struct {
	AccountID    string
	Provider     string
	ResourceType string
	Region       string
	Status       string
	Severity     string
	Q            string
}

type GraphFilter struct {
	AccountID    string
	Provider     string
	AssetID      string
	ResourceType string
	ResourceID   string
	Region       string
	Q            string
	Depth        int
	Limit        int
	Offset       int
}

type RuleFilter struct {
	AccountID    string
	Provider     string
	ResourceType string
	Region       string
	RuleID       string
	Severity     string
	Status       string
	Q            string
	Sort         string
	Limit        int
	Offset       int
}
