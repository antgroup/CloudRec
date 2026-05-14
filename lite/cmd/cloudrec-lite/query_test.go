package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/storage"
)

type cliQueryFixture struct {
	DBPath    string
	RulesDir  string
	AssetID   string
	FindingID string
	ScanRunID string
}

func TestRunDashboardQueryJSONAndTable(t *testing.T) {
	fixture := seedCLIQueryFixture(t)

	var jsonOut bytes.Buffer
	if err := runDashboardWithWriter([]string{"--db", fixture.DBPath, "--format", "json"}, &jsonOut); err != nil {
		t.Fatalf("dashboard json returned error: %v\n%s", err, jsonOut.String())
	}
	for _, want := range []string{`"asset_count": 2`, `"open_finding_count": 1`, `"high": 1`} {
		if !strings.Contains(jsonOut.String(), want) {
			t.Fatalf("dashboard json missing %q:\n%s", want, jsonOut.String())
		}
	}

	var tableOut bytes.Buffer
	if err := runDashboardWithWriter([]string{"--db", fixture.DBPath, "--format", "table"}, &tableOut); err != nil {
		t.Fatalf("dashboard table returned error: %v\n%s", err, tableOut.String())
	}
	for _, want := range []string{"Assets", "Open Risks", "Latest Scan"} {
		if !strings.Contains(tableOut.String(), want) {
			t.Fatalf("dashboard table missing %q:\n%s", want, tableOut.String())
		}
	}
}

func TestRunRisksQueryListShowAndCSV(t *testing.T) {
	fixture := seedCLIQueryFixture(t)

	var listOut bytes.Buffer
	if err := runRisksWithWriter([]string{"list", "--db", fixture.DBPath, "--severity", "high", "--format", "table"}, &listOut); err != nil {
		t.Fatalf("risks list returned error: %v\n%s", err, listOut.String())
	}
	for _, want := range []string{"mock.storage_bucket.public", "Public bucket", "high"} {
		if !strings.Contains(listOut.String(), want) {
			t.Fatalf("risks list missing %q:\n%s", want, listOut.String())
		}
	}

	var showOut bytes.Buffer
	if err := runRisksWithWriter([]string{"show", fixture.FindingID, "--db", fixture.DBPath, "--rules", fixture.RulesDir, "--provider", "mock", "--format", "json"}, &showOut); err != nil {
		t.Fatalf("risks show returned error: %v\n%s", err, showOut.String())
	}
	for _, want := range []string{fixture.FindingID, `"asset_resource_id": "bucket-public"`, "Disable public access"} {
		if !strings.Contains(showOut.String(), want) {
			t.Fatalf("risks show missing %q:\n%s", want, showOut.String())
		}
	}

	var csvOut bytes.Buffer
	if err := runRisksWithWriter([]string{"list", "--db", fixture.DBPath, "--status", "open", "--format", "csv"}, &csvOut); err != nil {
		t.Fatalf("risks csv returned error: %v\n%s", err, csvOut.String())
	}
	if !strings.Contains(csvOut.String(), "id,severity,status,rule_id,title,asset_id") {
		t.Fatalf("risks csv header missing:\n%s", csvOut.String())
	}
}

func TestRunAssetsQueryListAndShow(t *testing.T) {
	fixture := seedCLIQueryFixture(t)

	var listOut bytes.Buffer
	if err := runAssetsWithWriter([]string{"list", "--db", fixture.DBPath, "--resource-type", "storage_bucket", "--format", "table"}, &listOut); err != nil {
		t.Fatalf("assets list returned error: %v\n%s", err, listOut.String())
	}
	for _, want := range []string{"storage_bucket", "bucket-public", "cn-hangzhou"} {
		if !strings.Contains(listOut.String(), want) {
			t.Fatalf("assets list missing %q:\n%s", want, listOut.String())
		}
	}

	var showOut bytes.Buffer
	if err := runAssetsWithWriter([]string{"show", fixture.AssetID, "--db", fixture.DBPath, "--format", "json"}, &showOut); err != nil {
		t.Fatalf("assets show returned error: %v\n%s", err, showOut.String())
	}
	for _, want := range []string{fixture.AssetID, `"open_finding_count": 1`, `"relationships":`} {
		if !strings.Contains(showOut.String(), want) {
			t.Fatalf("assets show missing %q:\n%s", want, showOut.String())
		}
	}
}

func TestRunRulesQueryListShowAndCoverageAlias(t *testing.T) {
	fixture := seedCLIQueryFixture(t)

	var listOut bytes.Buffer
	if err := runRulesWithWriter([]string{"list", "--rules", fixture.RulesDir, "--provider", "mock", "--format", "table"}, &listOut); err != nil {
		t.Fatalf("rules list returned error: %v\n%s", err, listOut.String())
	}
	for _, want := range []string{"mock.storage_bucket.public", "storage_bucket", "high"} {
		if !strings.Contains(listOut.String(), want) {
			t.Fatalf("rules list missing %q:\n%s", want, listOut.String())
		}
	}

	var showOut bytes.Buffer
	if err := runRulesWithWriter([]string{"show", "mock.storage_bucket.public", "--rules", fixture.RulesDir, "--provider", "mock", "--format", "json"}, &showOut); err != nil {
		t.Fatalf("rules show returned error: %v\n%s", err, showOut.String())
	}
	for _, want := range []string{`"id": "mock.storage_bucket.public"`, `"remediation": "Disable public access."`} {
		if !strings.Contains(showOut.String(), want) {
			t.Fatalf("rules show missing %q:\n%s", want, showOut.String())
		}
	}

	var coverageOut bytes.Buffer
	if err := runRulesWithWriter([]string{"coverage", "--rules", fixture.RulesDir, "--provider", "mock", "--format", "json"}, &coverageOut); err != nil {
		t.Fatalf("rules coverage returned error: %v\n%s", err, coverageOut.String())
	}
	if !strings.Contains(coverageOut.String(), `"provider": "mock"`) {
		t.Fatalf("rules coverage should keep existing subcommand behavior:\n%s", coverageOut.String())
	}
}

func TestRunScansQueryListAndQuality(t *testing.T) {
	fixture := seedCLIQueryFixture(t)

	var listOut bytes.Buffer
	if err := runScansWithWriter([]string{"list", "--db", fixture.DBPath, "--format", "table"}, &listOut); err != nil {
		t.Fatalf("scans list returned error: %v\n%s", err, listOut.String())
	}
	for _, want := range []string{fixture.ScanRunID, "succeeded", "mock-account"} {
		if !strings.Contains(listOut.String(), want) {
			t.Fatalf("scans list missing %q:\n%s", want, listOut.String())
		}
	}

	var qualityOut bytes.Buffer
	if err := runScansWithWriter([]string{"quality", "--db", fixture.DBPath, "--rules", fixture.RulesDir, "--provider", "mock", "--format", "json"}, &qualityOut); err != nil {
		t.Fatalf("scans quality returned error: %v\n%s", err, qualityOut.String())
	}
	for _, want := range []string{`"assets_collected": 2`, `"findings": 1`, `"rule_quality_status"`} {
		if !strings.Contains(qualityOut.String(), want) {
			t.Fatalf("scans quality missing %q:\n%s", want, qualityOut.String())
		}
	}
}

func TestRunFacetsQuery(t *testing.T) {
	fixture := seedCLIQueryFixture(t)

	var out bytes.Buffer
	if err := runFacetsWithWriter([]string{"--db", fixture.DBPath, "--format", "table"}, &out); err != nil {
		t.Fatalf("facets returned error: %v\n%s", err, out.String())
	}
	for _, want := range []string{"accounts", "mock-account", "resource_types", "storage_bucket"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("facets output missing %q:\n%s", want, out.String())
		}
	}
}

func TestQueryListRejectsInvalidPagination(t *testing.T) {
	var out bytes.Buffer
	err := runAssetsWithWriter([]string{"list", "--limit", "0"}, &out)
	if err == nil || !strings.Contains(err.Error(), "limit must be positive") {
		t.Fatalf("expected invalid limit error, got %v", err)
	}

	err = runRisksWithWriter([]string{"list", "--offset", "-1"}, &out)
	if err == nil || !strings.Contains(err.Error(), "offset must be non-negative") {
		t.Fatalf("expected invalid offset error, got %v", err)
	}
}

func seedCLIQueryFixture(t *testing.T) cliQueryFixture {
	t.Helper()

	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	writeCLIRulePackWithRemediation(t, rulesDir, "mock-public-bucket", `{
		"id": "mock.storage_bucket.public",
		"name": "Mock public bucket",
		"severity": "high",
		"provider": "mock",
		"service": "storage",
		"asset_type": "storage_bucket",
		"categories": ["exposure"],
		"tags": ["public-access"],
		"remediation": "Disable public access."
	}`, `{"public": true}`)

	dbPath := filepath.Join(root, "cloudrec.db")
	ctx := context.Background()
	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if _, err := store.UpsertAccount(ctx, model.Account{ID: "mock-account", Provider: "mock", Name: "Mock Account"}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}
	run, err := store.CreateScanRun(ctx, model.ScanRun{
		AccountID: "mock-account",
		Provider:  "mock",
		Status:    model.ScanRunStatusRunning,
		StartedAt: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("create scan run: %v", err)
	}
	bucket, err := store.UpsertAsset(ctx, model.Asset{
		AccountID:    "mock-account",
		Provider:     "mock",
		ResourceType: "storage_bucket",
		ResourceID:   "bucket-public",
		Region:       "cn-hangzhou",
		Name:         "Public bucket",
		Properties:   json.RawMessage(`{"public":true}`),
	})
	if err != nil {
		t.Fatalf("upsert bucket: %v", err)
	}
	compute, err := store.UpsertAsset(ctx, model.Asset{
		AccountID:    "mock-account",
		Provider:     "mock",
		ResourceType: "compute_instance",
		ResourceID:   "i-demo",
		Region:       "cn-hangzhou",
		Name:         "Demo ECS",
		Properties:   json.RawMessage(`{"status":"running"}`),
	})
	if err != nil {
		t.Fatalf("upsert compute: %v", err)
	}
	if _, err := store.UpsertAssetRelationship(ctx, model.AssetRelationship{
		AccountID:          "mock-account",
		Provider:           "mock",
		SourceAssetID:      bucket.ID,
		SourceResourceType: bucket.ResourceType,
		SourceResourceID:   bucket.ResourceID,
		RelationshipType:   "related_to",
		TargetResourceID:   compute.ResourceID,
		Properties:         json.RawMessage(`{"reason":"unit-test"}`),
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	finding, err := store.UpsertFinding(ctx, model.Finding{
		ScanRunID:   run.ID,
		AccountID:   "mock-account",
		AssetID:     bucket.ID,
		RuleID:      "mock.storage_bucket.public",
		Title:       "Public bucket",
		Severity:    model.SeverityHigh,
		Status:      model.FindingStatusOpen,
		Message:     "Bucket is public.",
		Evidence:    json.RawMessage(`{"public":true}`),
		FirstSeenAt: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
		LastSeenAt:  time.Date(2026, 5, 9, 12, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("upsert finding: %v", err)
	}
	summary := json.RawMessage(`{"assets":2,"findings":1,"rules":1,"evaluated_rules":1,"skipped_rules":0,"collection_failures":0,"added_assets":2,"updated_assets":0,"missing_assets":0,"seen_assets":0}`)
	finished, err := store.FinishScanRun(ctx, run.ID, model.ScanRunStatusSucceeded, summary)
	if err != nil {
		t.Fatalf("finish scan run: %v", err)
	}

	return cliQueryFixture{
		DBPath:    dbPath,
		RulesDir:  rulesDir,
		AssetID:   bucket.ID,
		FindingID: finding.ID,
		ScanRunID: finished.ID,
	}
}

func writeCLIRulePackWithRemediation(t *testing.T, root string, name string, metadata string, input string) {
	t.Helper()

	writeCLIRulePack(t, root, name, metadata, input)
	if err := os.WriteFile(filepath.Join(root, name, "remediation.md"), []byte("Disable public access."), 0o644); err != nil {
		t.Fatalf("write remediation: %v", err)
	}
}
