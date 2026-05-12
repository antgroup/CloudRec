package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/model"
)

func TestSQLiteStoreCRUD(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)

	account, err := store.UpsertAccount(ctx, model.Account{
		ID:         "acct-1",
		Provider:   "mock",
		Name:       "Mock Account",
		ExternalID: "123456789012",
		Metadata:   json.RawMessage(`{"env":"test"}`),
	})
	if err != nil {
		t.Fatalf("upsert account: %v", err)
	}

	run, err := store.CreateScanRun(ctx, model.ScanRun{
		AccountID: account.ID,
		Provider:  account.Provider,
	})
	if err != nil {
		t.Fatalf("create scan run: %v", err)
	}
	if run.Status != model.ScanRunStatusRunning {
		t.Fatalf("expected running scan status, got %q", run.Status)
	}
	finishedRun, err := store.FinishScanRun(ctx, run.ID, model.ScanRunStatusSucceeded, json.RawMessage(`{"assets":1}`))
	if err != nil {
		t.Fatalf("finish scan run: %v", err)
	}
	if finishedRun.Status != model.ScanRunStatusSucceeded {
		t.Fatalf("expected succeeded scan status, got %q", finishedRun.Status)
	}
	if finishedRun.FinishedAt == nil {
		t.Fatal("expected finished_at to be set")
	}

	firstSeen := time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC)
	asset, err := store.UpsertAsset(ctx, model.Asset{
		AccountID:    account.ID,
		Provider:     account.Provider,
		ResourceType: "mock.bucket",
		ResourceID:   "bucket-1",
		Region:       "local",
		Name:         "bucket-one",
		Properties:   json.RawMessage(`{"public":true}`),
		FirstSeenAt:  firstSeen,
		LastSeenAt:   firstSeen,
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}

	updatedAsset, err := store.UpsertAsset(ctx, model.Asset{
		AccountID:    account.ID,
		Provider:     account.Provider,
		ResourceType: asset.ResourceType,
		ResourceID:   asset.ResourceID,
		Region:       "local",
		Name:         "bucket-renamed",
		Properties:   json.RawMessage(`{"public":false}`),
		LastSeenAt:   firstSeen.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("upsert existing asset: %v", err)
	}
	if updatedAsset.ID != asset.ID {
		t.Fatalf("expected asset upsert to keep id %q, got %q", asset.ID, updatedAsset.ID)
	}
	if updatedAsset.Name != "bucket-renamed" {
		t.Fatalf("expected updated asset name, got %q", updatedAsset.Name)
	}
	if !updatedAsset.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("expected first_seen_at to remain %s, got %s", firstSeen, updatedAsset.FirstSeenAt)
	}

	assets, err := store.ListAssets(ctx, AssetFilter{
		AccountID:    account.ID,
		ResourceType: asset.ResourceType,
		Limit:        10,
	})
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(assets) != 1 || assets[0].ID != asset.ID {
		t.Fatalf("unexpected assets: %+v", assets)
	}

	relationship, err := store.UpsertAssetRelationship(ctx, model.AssetRelationship{
		AccountID:          account.ID,
		Provider:           account.Provider,
		SourceAssetID:      asset.ID,
		SourceResourceType: asset.ResourceType,
		SourceResourceID:   asset.ResourceID,
		RelationshipType:   "member_of",
		TargetResourceID:   "vpc-1",
		Properties:         json.RawMessage(`{"primary":true}`),
		FirstSeenAt:        firstSeen,
		LastSeenAt:         firstSeen,
	})
	if err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	relationships, err := store.ListAssetRelationships(ctx, RelationshipFilter{
		AccountID:        account.ID,
		RelationshipType: "member_of",
		Limit:            10,
	})
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != relationship.ID {
		t.Fatalf("unexpected relationships: %+v", relationships)
	}

	state, err := store.UpsertAssetScanState(ctx, model.AssetScanState{
		ScanRunID:    run.ID,
		AccountID:    account.ID,
		AssetID:      asset.ID,
		ResourceType: asset.ResourceType,
		ResourceID:   asset.ResourceID,
		Status:       model.AssetScanStatusAdded,
	})
	if err != nil {
		t.Fatalf("upsert asset scan state: %v", err)
	}
	if state.Status != model.AssetScanStatusAdded {
		t.Fatalf("expected added scan state, got %q", state.Status)
	}

	finding, err := store.UpsertFinding(ctx, model.Finding{
		ScanRunID:   run.ID,
		AccountID:   account.ID,
		AssetID:     asset.ID,
		RuleID:      "MOCK_BUCKET_PUBLIC",
		Title:       "Bucket allows public access",
		Severity:    model.SeverityHigh,
		Message:     "The bucket policy allows public reads.",
		Evidence:    json.RawMessage(`{"policy":"public-read"}`),
		Remediation: "Disable public access.",
		FirstSeenAt: firstSeen,
		LastSeenAt:  firstSeen,
	})
	if err != nil {
		t.Fatalf("upsert finding: %v", err)
	}
	if finding.Status != model.FindingStatusOpen {
		t.Fatalf("expected default open finding status, got %q", finding.Status)
	}

	updatedFinding, err := store.UpsertFinding(ctx, model.Finding{
		ScanRunID:   run.ID,
		AccountID:   account.ID,
		AssetID:     asset.ID,
		RuleID:      finding.RuleID,
		Title:       finding.Title,
		Severity:    model.SeverityCritical,
		Status:      model.FindingStatusOpen,
		Message:     "The bucket policy now allows public writes.",
		Evidence:    json.RawMessage(`{"policy":"public-write"}`),
		Remediation: "Block public access and rotate exposed data.",
		LastSeenAt:  firstSeen.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("upsert existing finding: %v", err)
	}
	if updatedFinding.ID != finding.ID {
		t.Fatalf("expected finding upsert to keep id %q, got %q", finding.ID, updatedFinding.ID)
	}
	if updatedFinding.Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity, got %q", updatedFinding.Severity)
	}
	if !updatedFinding.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("expected first_seen_at to remain %s, got %s", firstSeen, updatedFinding.FirstSeenAt)
	}

	findings, err := store.ListFindings(ctx, FindingFilter{
		AccountID:    account.ID,
		ScanRunID:    run.ID,
		ResourceType: asset.ResourceType,
		Severity:     model.SeverityCritical,
		Status:       model.FindingStatusOpen,
		Limit:        10,
	})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != finding.ID {
		t.Fatalf("expected finding id %q, got %q", finding.ID, findings[0].ID)
	}

	runs, err := store.ListScanRuns(ctx, ScanRunFilter{
		AccountID: account.ID,
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("list scan runs: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != run.ID {
		t.Fatalf("unexpected scan runs: %+v", runs)
	}

	summary, err := store.GetSummary(ctx, SummaryFilter{AccountID: account.ID})
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if summary.AssetCount != 1 || summary.RelationshipCount != 1 || summary.FindingCount != 1 || summary.OpenFindingCount != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if summary.SeverityCounts[model.SeverityCritical] != 1 {
		t.Fatalf("expected critical severity count 1, got %+v", summary.SeverityCounts)
	}
}

func TestSQLiteStoreInitIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)

	if err := store.Init(ctx); err != nil {
		t.Fatalf("second init failed: %v", err)
	}
}

func TestSQLiteStoreWebReadModels(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)

	account, run, bucket, database, finding := seedWebReadModels(t, ctx, store)

	assetPage, err := store.ListAssetsWithTotal(ctx, AssetFilter{
		AccountID: account.ID,
		Region:    "cn-hangzhou",
		Q:         "public",
		Sort:      "name",
		Limit:     1,
	})
	if err != nil {
		t.Fatalf("list assets with total: %v", err)
	}
	if assetPage.Total != 1 || len(assetPage.Assets) != 1 || assetPage.Assets[0].ID != bucket.ID {
		t.Fatalf("unexpected asset page: %+v", assetPage)
	}

	offsetPage, err := store.ListAssetsWithTotal(ctx, AssetFilter{
		AccountID: account.ID,
		Sort:      "-last_seen_at",
		Limit:     1,
		Offset:    1,
	})
	if err != nil {
		t.Fatalf("list assets with offset: %v", err)
	}
	if offsetPage.Total != 2 || len(offsetPage.Assets) != 1 || offsetPage.Assets[0].ID != bucket.ID {
		t.Fatalf("unexpected offset asset page: %+v", offsetPage)
	}

	findingViews, err := store.ListFindingViews(ctx, FindingFilter{
		AccountID: account.ID,
		Region:    "cn-hangzhou",
		Q:         "public",
		Sort:      "-severity",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("list finding views: %v", err)
	}
	if findingViews.Total != 1 || len(findingViews.Findings) != 1 {
		t.Fatalf("unexpected finding views: %+v", findingViews)
	}
	if findingViews.Findings[0].ID != finding.ID || findingViews.Findings[0].AssetResourceID != bucket.ResourceID {
		t.Fatalf("finding view did not include joined asset fields: %+v", findingViews.Findings[0])
	}

	findingDetail, err := store.GetFindingView(ctx, finding.ID)
	if err != nil {
		t.Fatalf("get finding view: %v", err)
	}
	if findingDetail.Asset.ID != bucket.ID || findingDetail.Region != bucket.Region {
		t.Fatalf("unexpected finding detail: %+v", findingDetail)
	}

	assetDetail, err := store.GetAssetView(ctx, bucket.ID)
	if err != nil {
		t.Fatalf("get asset view: %v", err)
	}
	if assetDetail.FindingCount != 1 || assetDetail.OpenFindingCount != 1 || assetDetail.SeverityCounts[model.SeverityHigh] != 1 {
		t.Fatalf("unexpected asset detail counts: %+v", assetDetail)
	}
	if len(assetDetail.Relationships) != 1 || assetDetail.Relationships[0].TargetResourceID != database.ResourceID {
		t.Fatalf("unexpected asset relationships: %+v", assetDetail.Relationships)
	}
	if len(assetDetail.Findings) != 1 || assetDetail.Findings[0].RuleID != finding.RuleID {
		t.Fatalf("unexpected asset findings: %+v", assetDetail.Findings)
	}

	facets, err := store.GetFacets(ctx, FacetFilter{AccountID: account.ID})
	if err != nil {
		t.Fatalf("get facets: %v", err)
	}
	if !facetHas(facets.Regions, "cn-hangzhou", 1) || !facetHas(facets.ResourceTypes, "storage.bucket", 1) {
		t.Fatalf("unexpected asset facets: %+v", facets)
	}
	if !facetHas(facets.Severities, model.SeverityHigh, 1) || !facetHas(facets.Statuses, model.FindingStatusOpen, 1) {
		t.Fatalf("unexpected finding facets: %+v", facets)
	}

	dashboard, err := store.GetDashboard(ctx, DashboardFilter{AccountID: account.ID})
	if err != nil {
		t.Fatalf("get dashboard: %v", err)
	}
	if dashboard.AssetCount != 2 || dashboard.FindingCount != 2 || dashboard.OpenFindingCount != 1 || dashboard.RuleCount != 2 {
		t.Fatalf("unexpected dashboard counts: %+v", dashboard)
	}
	if dashboard.LatestScanRun == nil || dashboard.LatestScanRun.ID != run.ID || dashboard.ScanDelta.AddedAssets != 2 {
		t.Fatalf("unexpected dashboard scan summary: %+v", dashboard)
	}
	if len(dashboard.RecentFindings) == 0 || len(dashboard.RecentAssets) == 0 {
		t.Fatalf("expected dashboard recents: %+v", dashboard)
	}

	graph, err := store.GetGraph(ctx, GraphFilter{
		AccountID: account.ID,
		AssetID:   bucket.ID,
	})
	if err != nil {
		t.Fatalf("get graph: %v", err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].TargetID != database.ID {
		t.Fatalf("unexpected graph edges: %+v", graph)
	}
	if !graphHasNode(graph.Nodes, bucket.ID) || !graphHasNode(graph.Nodes, database.ID) {
		t.Fatalf("unexpected graph nodes: %+v", graph.Nodes)
	}

	rules, err := store.ListRules(ctx, RuleFilter{
		AccountID: account.ID,
		Sort:      "-finding_count",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if rules.Total != 2 || len(rules.Rules) != 2 {
		t.Fatalf("unexpected rules: %+v", rules)
	}

	rule, err := store.GetRule(ctx, finding.RuleID)
	if err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if rule.RuleID != finding.RuleID || rule.OpenFindingCount != 1 || len(rule.Findings) != 1 {
		t.Fatalf("unexpected rule detail: %+v", rule)
	}
}

func openTestStore(t *testing.T, ctx context.Context) *SQLiteStore {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "cloudrec-lite.db")
	store, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	if err := store.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	return store
}

func seedWebReadModels(t *testing.T, ctx context.Context, store *SQLiteStore) (model.Account, model.ScanRun, model.Asset, model.Asset, model.Finding) {
	t.Helper()

	account, err := store.UpsertAccount(ctx, model.Account{
		ID:         "web-acct",
		Provider:   "mock",
		Name:       "Web Account",
		ExternalID: "web-acct",
	})
	if err != nil {
		t.Fatalf("upsert account: %v", err)
	}

	run, err := store.CreateScanRun(ctx, model.ScanRun{
		ID:        "web-run",
		AccountID: account.ID,
		Provider:  account.Provider,
		StartedAt: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("create scan run: %v", err)
	}

	firstSeen := time.Date(2026, 5, 1, 10, 30, 0, 0, time.UTC)
	bucket, err := store.UpsertAsset(ctx, model.Asset{
		ID:           "asset-bucket",
		AccountID:    account.ID,
		Provider:     account.Provider,
		ResourceType: "storage.bucket",
		ResourceID:   "bucket-public",
		Region:       "cn-hangzhou",
		Name:         "Public Bucket",
		Properties:   json.RawMessage(`{"public":true}`),
		FirstSeenAt:  firstSeen,
		LastSeenAt:   firstSeen,
	})
	if err != nil {
		t.Fatalf("upsert bucket asset: %v", err)
	}

	database, err := store.UpsertAsset(ctx, model.Asset{
		ID:           "asset-db",
		AccountID:    account.ID,
		Provider:     account.Provider,
		ResourceType: "database.instance",
		ResourceID:   "db-private",
		Region:       "cn-shanghai",
		Name:         "Private DB",
		Properties:   json.RawMessage(`{"engine":"sqlite"}`),
		FirstSeenAt:  firstSeen.Add(time.Minute),
		LastSeenAt:   firstSeen.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("upsert database asset: %v", err)
	}

	if _, err := store.UpsertAssetRelationship(ctx, model.AssetRelationship{
		ID:                 "rel-bucket-db",
		AccountID:          account.ID,
		Provider:           account.Provider,
		SourceAssetID:      bucket.ID,
		SourceResourceType: bucket.ResourceType,
		SourceResourceID:   bucket.ResourceID,
		RelationshipType:   "uses",
		TargetResourceID:   database.ResourceID,
		Properties:         json.RawMessage(`{"path":"backup"}`),
		FirstSeenAt:        firstSeen,
		LastSeenAt:         firstSeen,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	finding, err := store.UpsertFinding(ctx, model.Finding{
		ID:          "finding-public",
		ScanRunID:   run.ID,
		AccountID:   account.ID,
		AssetID:     bucket.ID,
		RuleID:      "rule.public.bucket",
		Title:       "Public bucket",
		Severity:    model.SeverityHigh,
		Status:      model.FindingStatusOpen,
		Message:     "Bucket is public to the internet",
		Evidence:    json.RawMessage(`{"acl":"public"}`),
		Remediation: "Disable public access.",
		FirstSeenAt: firstSeen,
		LastSeenAt:  firstSeen,
	})
	if err != nil {
		t.Fatalf("upsert finding: %v", err)
	}

	if _, err := store.UpsertFinding(ctx, model.Finding{
		ID:          "finding-db",
		ScanRunID:   run.ID,
		AccountID:   account.ID,
		AssetID:     database.ID,
		RuleID:      "rule.db.backup",
		Title:       "Database backup disabled",
		Severity:    model.SeverityLow,
		Status:      model.FindingStatusResolved,
		Message:     "Backups are disabled.",
		Evidence:    json.RawMessage(`{"backup":false}`),
		Remediation: "Enable backups.",
		FirstSeenAt: firstSeen,
		LastSeenAt:  firstSeen.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert database finding: %v", err)
	}

	finishedRun, err := store.FinishScanRun(ctx, run.ID, model.ScanRunStatusSucceeded, json.RawMessage(`{"assets":2,"findings":2,"added_assets":2}`))
	if err != nil {
		t.Fatalf("finish scan run: %v", err)
	}

	return account, finishedRun, bucket, database, finding
}

func facetHas(values []model.FacetValue, value string, count int) bool {
	for _, item := range values {
		if item.Value == value && item.Count == count {
			return true
		}
	}
	return false
}

func graphHasNode(nodes []model.GraphNode, id string) bool {
	for _, node := range nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}
