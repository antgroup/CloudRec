package model

import (
	"encoding/json"
	"time"
)

const (
	ScanRunStatusRunning   = "running"
	ScanRunStatusSucceeded = "succeeded"
	ScanRunStatusFailed    = "failed"
)

const (
	FindingStatusOpen       = "open"
	FindingStatusResolved   = "resolved"
	FindingStatusSuppressed = "suppressed"
)

const (
	AssetScanStatusAdded   = "added"
	AssetScanStatusUpdated = "updated"
	AssetScanStatusSeen    = "seen"
	AssetScanStatusMissing = "missing"
)

const (
	SeverityUnknown  = "unknown"
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

type Account struct {
	ID         string          `json:"id"`
	Provider   string          `json:"provider"`
	Name       string          `json:"name"`
	ExternalID string          `json:"external_id"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type Asset struct {
	ID           string          `json:"id"`
	AccountID    string          `json:"account_id"`
	Provider     string          `json:"provider"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Region       string          `json:"region,omitempty"`
	Name         string          `json:"name,omitempty"`
	Properties   json.RawMessage `json:"properties,omitempty"`
	FirstSeenAt  time.Time       `json:"first_seen_at"`
	LastSeenAt   time.Time       `json:"last_seen_at"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type AssetRelationship struct {
	ID                 string          `json:"id"`
	AccountID          string          `json:"account_id"`
	Provider           string          `json:"provider"`
	SourceAssetID      string          `json:"source_asset_id"`
	SourceResourceType string          `json:"source_resource_type"`
	SourceResourceID   string          `json:"source_resource_id"`
	RelationshipType   string          `json:"relationship_type"`
	TargetResourceID   string          `json:"target_resource_id"`
	Properties         json.RawMessage `json:"properties,omitempty"`
	FirstSeenAt        time.Time       `json:"first_seen_at"`
	LastSeenAt         time.Time       `json:"last_seen_at"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type ScanRun struct {
	ID         string          `json:"id"`
	AccountID  string          `json:"account_id"`
	Provider   string          `json:"provider"`
	Status     string          `json:"status"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Summary    json.RawMessage `json:"summary,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type ScanTaskRun struct {
	ID           string    `json:"id"`
	ScanRunID    string    `json:"scan_run_id"`
	AccountID    string    `json:"account_id"`
	Provider     string    `json:"provider"`
	Scope        string    `json:"scope,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	Region       string    `json:"region,omitempty"`
	Status       string    `json:"status"`
	Category     string    `json:"category,omitempty"`
	Message      string    `json:"message,omitempty"`
	AssetCount   int       `json:"asset_count"`
	Attempt      int       `json:"attempt"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	DurationMs   int64     `json:"duration_ms"`
	CreatedAt    time.Time `json:"created_at"`
}

type ScanTaskSummary struct {
	Total      int                   `json:"total"`
	Succeeded  int                   `json:"succeeded"`
	Failed     int                   `json:"failed"`
	Skipped    int                   `json:"skipped"`
	DurationMs int64                 `json:"duration_ms"`
	Slowest    []ScanTaskSummaryItem `json:"slowest,omitempty"`
}

type ScanTaskSummaryItem struct {
	Scope        string `json:"scope,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Region       string `json:"region,omitempty"`
	Status       string `json:"status"`
	Category     string `json:"category,omitempty"`
	Message      string `json:"message,omitempty"`
	AssetCount   int    `json:"asset_count"`
	DurationMs   int64  `json:"duration_ms"`
}

type CollectorSkipEntry struct {
	ID           string    `json:"id"`
	AccountID    string    `json:"account_id"`
	Provider     string    `json:"provider"`
	ResourceType string    `json:"resource_type"`
	Region       string    `json:"region"`
	Category     string    `json:"category"`
	Message      string    `json:"message,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Finding struct {
	ID          string          `json:"id"`
	ScanRunID   string          `json:"scan_run_id"`
	AccountID   string          `json:"account_id"`
	AssetID     string          `json:"asset_id"`
	RuleID      string          `json:"rule_id"`
	Title       string          `json:"title"`
	Severity    string          `json:"severity"`
	Status      string          `json:"status"`
	Message     string          `json:"message,omitempty"`
	Evidence    json.RawMessage `json:"evidence,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type Waiver struct {
	ID        string     `json:"id"`
	AccountID string     `json:"account_id"`
	AssetID   *string    `json:"asset_id,omitempty"`
	RuleID    string     `json:"rule_id"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type AssetScanState struct {
	ID           string    `json:"id"`
	ScanRunID    string    `json:"scan_run_id"`
	AccountID    string    `json:"account_id"`
	AssetID      string    `json:"asset_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Summary struct {
	AccountID         string         `json:"account_id,omitempty"`
	AssetCount        int            `json:"asset_count"`
	FindingCount      int            `json:"finding_count"`
	OpenFindingCount  int            `json:"open_finding_count"`
	RelationshipCount int            `json:"relationship_count"`
	SeverityCounts    map[string]int `json:"severity_counts"`
	LatestScanRun     *ScanRun       `json:"latest_scan_run,omitempty"`
	ScanDelta         ScanDelta      `json:"scan_delta"`
}

type ScanDelta struct {
	AddedAssets   int `json:"added_assets"`
	UpdatedAssets int `json:"updated_assets"`
	MissingAssets int `json:"missing_assets"`
	SeenAssets    int `json:"seen_assets"`
}

type FacetValue struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
	Count int    `json:"count"`
}

type FacetSet struct {
	Accounts      []FacetValue `json:"accounts"`
	Providers     []FacetValue `json:"providers"`
	Regions       []FacetValue `json:"regions"`
	ResourceTypes []FacetValue `json:"resource_types"`
	AssetTypes    []FacetValue `json:"asset_types"`
	Severities    []FacetValue `json:"severities"`
	Statuses      []FacetValue `json:"statuses"`
	Rules         []FacetValue `json:"rules"`
}

type AccountSummary struct {
	ID         string `json:"id"`
	Provider   string `json:"provider,omitempty"`
	Name       string `json:"name,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

type AssetSummary struct {
	ID           string `json:"id"`
	AccountID    string `json:"account_id"`
	Provider     string `json:"provider"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Region       string `json:"region,omitempty"`
	Name         string `json:"name,omitempty"`
}

type FindingView struct {
	Finding
	Asset             AssetSummary `json:"asset"`
	Provider          string       `json:"provider"`
	Region            string       `json:"region,omitempty"`
	AssetResourceType string       `json:"asset_resource_type"`
	AssetResourceID   string       `json:"asset_resource_id"`
	AssetName         string       `json:"asset_name,omitempty"`
}

type AssetView struct {
	Asset
	FindingCount         int                 `json:"finding_count"`
	OpenFindingCount     int                 `json:"open_finding_count"`
	CriticalFindingCount int                 `json:"critical_finding_count"`
	HighFindingCount     int                 `json:"high_finding_count"`
	SeverityCounts       map[string]int      `json:"severity_counts,omitempty"`
	ProductSummary       map[string]any      `json:"product_summary,omitempty"`
	Relationships        []AssetRelationship `json:"relationships,omitempty"`
	Findings             []FindingView       `json:"findings,omitempty"`
}

type RuleView struct {
	ID                 string         `json:"id"`
	RuleID             string         `json:"rule_id"`
	Title              string         `json:"title"`
	Severity           string         `json:"severity"`
	Remediation        string         `json:"remediation,omitempty"`
	FindingCount       int            `json:"finding_count"`
	OpenFindingCount   int            `json:"open_finding_count"`
	AffectedAssetCount int            `json:"affected_asset_count"`
	AssetCount         int            `json:"asset_count"`
	FirstSeenAt        time.Time      `json:"first_seen_at"`
	LastSeenAt         time.Time      `json:"last_seen_at"`
	SeverityCounts     map[string]int `json:"severity_counts,omitempty"`
	StatusCounts       map[string]int `json:"status_counts,omitempty"`
	Findings           []FindingView  `json:"findings,omitempty"`
}

type GraphNode struct {
	ID               string          `json:"id"`
	Label            string          `json:"label"`
	Kind             string          `json:"kind"`
	AccountID        string          `json:"account_id,omitempty"`
	Provider         string          `json:"provider,omitempty"`
	ResourceType     string          `json:"resource_type,omitempty"`
	ResourceID       string          `json:"resource_id,omitempty"`
	Region           string          `json:"region,omitempty"`
	Severity         string          `json:"severity,omitempty"`
	FindingCount     int             `json:"finding_count,omitempty"`
	OpenFindingCount int             `json:"open_finding_count,omitempty"`
	Properties       json.RawMessage `json:"properties,omitempty"`
}

type GraphEdge struct {
	ID               string          `json:"id"`
	SourceID         string          `json:"source_id"`
	TargetID         string          `json:"target_id"`
	Source           string          `json:"source"`
	Target           string          `json:"target"`
	RelationshipType string          `json:"relationship_type"`
	Label            string          `json:"label,omitempty"`
	Properties       json.RawMessage `json:"properties,omitempty"`
}

type GraphResponse struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type Dashboard struct {
	AccountID            string         `json:"account_id,omitempty"`
	Summary              Summary        `json:"summary"`
	AssetCount           int            `json:"asset_count"`
	FindingCount         int            `json:"finding_count"`
	OpenFindingCount     int            `json:"open_finding_count"`
	CriticalFindingCount int            `json:"critical_finding_count"`
	HighFindingCount     int            `json:"high_finding_count"`
	RelationshipCount    int            `json:"relationship_count"`
	RuleCount            int            `json:"rule_count"`
	AccountCount         int            `json:"account_count"`
	SeverityCounts       map[string]int `json:"severity_counts"`
	StatusCounts         map[string]int `json:"status_counts"`
	ProviderCounts       []FacetValue   `json:"provider_counts"`
	RegionCounts         []FacetValue   `json:"region_counts"`
	ResourceTypeCounts   []FacetValue   `json:"resource_type_counts"`
	LatestScanRun        *ScanRun       `json:"latest_scan_run,omitempty"`
	ScanDelta            ScanDelta      `json:"scan_delta"`
	RecentFindings       []FindingView  `json:"recent_findings,omitempty"`
	RecentAssets         []AssetView    `json:"recent_assets,omitempty"`
}

type AssetList struct {
	Assets []Asset `json:"assets"`
	Total  int     `json:"total"`
	Offset int     `json:"offset,omitempty"`
	Limit  int     `json:"limit,omitempty"`
}

type AssetViewList struct {
	Assets []AssetView `json:"assets"`
	Total  int         `json:"total"`
	Offset int         `json:"offset,omitempty"`
	Limit  int         `json:"limit,omitempty"`
}

type FindingList struct {
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
	Offset   int       `json:"offset,omitempty"`
	Limit    int       `json:"limit,omitempty"`
}

type FindingViewList struct {
	Findings []FindingView `json:"findings"`
	Total    int           `json:"total"`
	Offset   int           `json:"offset,omitempty"`
	Limit    int           `json:"limit,omitempty"`
}

type ScanRunList struct {
	ScanRuns []ScanRun `json:"scan_runs"`
	Total    int       `json:"total"`
	Offset   int       `json:"offset,omitempty"`
	Limit    int       `json:"limit,omitempty"`
}

type AssetRelationshipList struct {
	Relationships []AssetRelationship `json:"relationships"`
	Total         int                 `json:"total"`
	Offset        int                 `json:"offset,omitempty"`
	Limit         int                 `json:"limit,omitempty"`
}

type RuleList struct {
	Rules  []RuleView `json:"rules"`
	Total  int        `json:"total"`
	Offset int        `json:"offset,omitempty"`
	Limit  int        `json:"limit,omitempty"`
}
