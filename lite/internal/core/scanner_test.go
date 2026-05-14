package core

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/collectorstate"
	"github.com/antgroup/CloudRec/lite/internal/model"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
	"github.com/antgroup/CloudRec/lite/internal/rule"
	"github.com/antgroup/CloudRec/lite/internal/storage"
)

func TestDefaultDBPathUsesUserConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("user config dir: %v", err)
	}
	want := filepath.Join(configDir, "cloudrec-lite", "cloudrec-lite.db")
	if got := DefaultDBPath(); got != want {
		t.Fatalf("DefaultDBPath() = %q, want %q", got, want)
	}
}

func TestScannerScanRequiresProvider(t *testing.T) {
	_, err := NewScanner().Scan(ScanOptions{Account: "default"})
	if err == nil {
		t.Fatal("expected missing provider error")
	}
}

func TestScannerDryRun(t *testing.T) {
	result, err := NewScanner().Scan(ScanOptions{
		Provider: "mock",
		Account:  "default",
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if !result.DryRun {
		t.Fatal("expected dry run result")
	}
	if result.AssetCount != 3 {
		t.Fatalf("asset count = %d, want 3", result.AssetCount)
	}
	if result.FindingCount != 1 {
		t.Fatalf("finding count = %d, want 1", result.FindingCount)
	}
}

func TestScannerProgressReporterIncludesStagesAndPending(t *testing.T) {
	var progress bytes.Buffer
	result, err := NewScanner().Scan(ScanOptions{
		Provider: "mock",
		Account:  "default",
		DryRun:   true,
		Progress: &progress,
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if result.AssetCount != 3 {
		t.Fatalf("asset count = %d, want 3", result.AssetCount)
	}

	output := progress.String()
	for _, want := range []string{
		"[progress] scan",
		"current=\"collect assets\"",
		"eta=",
		"pending=",
		"[progress] evaluate rules",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("progress output missing %q:\n%s", want, output)
		}
	}
}

func TestScannerPersistsScan(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cloudrec-lite.db")

	result, err := NewScanner().ScanContext(ctx, ScanOptions{
		Provider: "mock",
		Account:  "default",
		DBPath:   dbPath,
		DryRun:   false,
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if result.ScanRunID == "" {
		t.Fatal("expected persisted scan run id")
	}
	if result.FindingCount != 1 {
		t.Fatalf("finding count = %d, want 1", result.FindingCount)
	}

	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})

	findings, err := store.ListFindings(ctx, storage.FindingFilter{
		AccountID: result.Account,
		ScanRunID: result.ScanRunID,
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("stored findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "mock.storage_bucket.public" {
		t.Fatalf("stored finding rule id = %q", findings[0].RuleID)
	}

	relationships, err := store.ListAssetRelationships(ctx, storage.RelationshipFilter{
		AccountID:        result.Account,
		RelationshipType: "member_of",
		Limit:            10,
	})
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 {
		t.Fatalf("stored relationships = %d, want 1", len(relationships))
	}
	if relationships[0].TargetResourceID == "" {
		t.Fatal("expected relationship target resource id")
	}

	runs, err := store.ListScanRuns(ctx, storage.ScanRunFilter{
		AccountID: result.Account,
		Limit:     1,
	})
	if err != nil {
		t.Fatalf("list scan runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("stored scan runs = %d, want 1", len(runs))
	}
	var summary map[string]any
	if err := json.Unmarshal(runs[0].Summary, &summary); err != nil {
		t.Fatalf("decode scan summary: %v", err)
	}
	if intFromSummary(summary["added_assets"]) != 3 || intFromSummary(summary["missing_assets"]) != 0 {
		t.Fatalf("unexpected scan summary delta: %+v", summary)
	}

	apiSummary, err := store.GetSummary(ctx, storage.SummaryFilter{AccountID: result.Account})
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if apiSummary.AssetCount != 3 || apiSummary.RelationshipCount != 1 || apiSummary.ScanDelta.AddedAssets != 3 {
		t.Fatalf("unexpected persisted summary: %+v", apiSummary)
	}
}

func TestScannerAliCloudFixtureScan(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "metadata.json"), `{
		"id": "alicloud.oss.public_read_write",
		"name": "OSS public read write",
		"severity": "high",
		"provider": "alicloud",
		"service": "oss",
		"asset_type": "oss",
		"query": "data.test_alicloud_oss.risk"
	}`)
	writeTestFile(t, filepath.Join(dir, "policy.rego"), `package test_alicloud_oss
import rego.v1

default risk := false

risk if {
	input.BucketInfo.ACL == "public-read-write"
}`)
	writeTestFile(t, filepath.Join(dir, "input.json"), `{
		"BucketInfo": {
			"ACL": "public-read-write",
			"Name": "public-bucket"
		},
		"BucketProperties": {
			"Region": "cn-hangzhou"
		}
	}`)

	result, err := NewScanner().Scan(ScanOptions{
		Provider: "alicloud",
		Account:  "demo",
		RulesDir: dir,
		DryRun:   true,
		Config: map[string]string{
			"fixture": dir,
		},
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if result.AssetCount != 1 {
		t.Fatalf("asset count = %d, want 1", result.AssetCount)
	}
	if result.FindingCount != 1 {
		t.Fatalf("finding count = %d, want 1", result.FindingCount)
	}
}

func TestScannerContinuesWithPartialCollectionFailures(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "metadata.json"), `{
		"id": "test.partial",
		"name": "partial collection rule",
		"severity": "low",
		"provider": "partial",
		"asset_type": "bucket",
		"query": "data.test_partial.risk"
	}`)
	writeTestFile(t, filepath.Join(dir, "policy.rego"), `package test_partial
import rego.v1

default risk := false

risk if {
	input.name == "kept"
}`)

	scanner := NewScanner()
	scanner.RegisterProvider(partialProvider{})

	result, err := scanner.Scan(ScanOptions{
		Provider: "partial",
		Account:  "default",
		RulesDir: dir,
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if result.AssetCount != 1 {
		t.Fatalf("asset count = %d, want 1", result.AssetCount)
	}
	if result.FindingCount != 1 {
		t.Fatalf("finding count = %d, want 1", result.FindingCount)
	}
	if result.CollectionFailureCount != 1 {
		t.Fatalf("collection failures = %d, want 1", result.CollectionFailureCount)
	}
	if result.CollectionFailures[0].ResourceType != "OSS" {
		t.Fatalf("failure resource type = %q, want OSS", result.CollectionFailures[0].ResourceType)
	}
}

func TestScannerAppliesLegacyLinkedDataListInputs(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestFile(t, filepath.Join(rulesDir, "metadata.json"), `{
		"id": "test.ens.agent",
		"name": "ENS agent",
		"severity": "medium",
		"provider": "linktest",
		"asset_type": "ens_instance",
		"query": "data.test_ens_agent.risk",
		"legacy": {
			"linkedDataList": "[{\"associativeMode\":\"仅关联一次\",\"linkedKey1\":\"$.Instance.InstanceId\",\"linkedKey2\":\"$.Instance.InstanceId\",\"newKeyName\":\"InstanceInstalledAegis\",\"resourceType\":[\"SECURITY\",\"Sas\"]}]"
		}
	}`)
	writeTestFile(t, filepath.Join(rulesDir, "policy.rego"), `package test_ens_agent
import rego.v1

default risk := false

risk if {
	agent := input.InstanceInstalledAegis
	lower(agent.Instance.ClientStatus) == "offline"
}`)

	packs, err := rule.LoadDir(rulesDir)
	if err != nil {
		t.Fatalf("load linked rule: %v", err)
	}
	assets, err := (linkedProvider{clientStatus: "offline", authVersion: 1}).CollectAssets(context.Background(), liteprovider.Account{Provider: "linktest", AccountID: "default"})
	if err != nil {
		t.Fatalf("collect linked assets: %v", err)
	}
	input := assetRuleInput(assets[0])
	applyLinkedRuleInputs(input, assets[0], packs, newLinkedAssetResolver(assets))
	if _, ok := input["InstanceInstalledAegis"]; !ok {
		t.Fatalf("linked input was not injected: %#v", input)
	}
	findings, _, err := NewScanner().evaluateAsset(context.Background(), packs, input)
	if err != nil {
		t.Fatalf("evaluate linked input: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("linked input findings = %d, want 1; input=%#v", len(findings), input)
	}

	scanner := NewScanner()
	scanner.RegisterProvider(linkedProvider{clientStatus: "offline", authVersion: 1})
	result, err := scanner.Scan(ScanOptions{
		Provider: "linktest",
		Account:  "default",
		RulesDir: rulesDir,
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("scan with linked data returned error: %v", err)
	}
	if result.AssetCount != 2 || result.FindingCount != 1 {
		t.Fatalf("result = %+v, want two assets and one finding from linked Sas input", result)
	}

	scanner = NewScanner()
	scanner.RegisterProvider(linkedProvider{clientStatus: "online", authVersion: 1})
	result, err = scanner.Scan(ScanOptions{
		Provider: "linktest",
		Account:  "default",
		RulesDir: rulesDir,
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("scan with online linked data returned error: %v", err)
	}
	if result.FindingCount != 0 {
		t.Fatalf("finding count = %d, want 0 for online lower-edition agent", result.FindingCount)
	}
}

func TestScannerPersistsCollectionTelemetryAndSkipCache(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cloudrec-lite.db")
	rulesDir := t.TempDir()
	writeTestFile(t, filepath.Join(rulesDir, "metadata.json"), `{
		"id": "test.telemetry",
		"name": "telemetry",
		"severity": "low",
		"provider": "telemetry",
		"asset_type": "bucket",
		"query": "data.test_telemetry.risk"
	}`)
	writeTestFile(t, filepath.Join(rulesDir, "policy.rego"), `package test_telemetry
import rego.v1

default risk := false
`)

	scanner := NewScanner()
	scanner.RegisterProvider(telemetryProvider{})
	result, err := scanner.ScanContext(ctx, ScanOptions{
		Provider: "telemetry",
		Account:  "default",
		RulesDir: rulesDir,
		DBPath:   dbPath,
		DryRun:   false,
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if result.CollectionTaskSummary.Total != 2 || result.CollectionTaskSummary.Failed != 1 {
		t.Fatalf("collection task summary = %+v, want 2 total and 1 failed", result.CollectionTaskSummary)
	}

	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	tasks, err := store.ListScanTaskRuns(ctx, storage.ScanTaskRunFilter{
		ScanRunID: result.ScanRunID,
		Sort:      "resource_type",
	})
	if err != nil {
		t.Fatalf("list scan task runs: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("scan task runs = %d, want 2", len(tasks))
	}
	entries, err := store.ListActiveCollectorSkipEntries(ctx, "telemetry", "default", time.Now().UTC())
	if err != nil {
		t.Fatalf("list skip cache: %v", err)
	}
	if len(entries) != 1 || entries[0].ResourceType != "queue" || entries[0].Category != "unsupported_region" {
		t.Fatalf("skip entries = %+v, want queue unsupported_region", entries)
	}
}

func TestScannerCreatesDefaultDBParentDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	dbPath := DefaultDBPath()
	if _, err := os.Stat(filepath.Dir(dbPath)); !os.IsNotExist(err) {
		t.Fatalf("expected default db parent to start missing, stat err=%v", err)
	}

	result, err := NewScanner().Scan(ScanOptions{
		Provider: "mock",
		Account:  "default",
		DryRun:   false,
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if result.ScanRunID == "" {
		t.Fatal("expected persisted scan run id")
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected default db to be created at %q: %v", dbPath, err)
	}
}

func TestScannerScanDeltaDetectsMissingAssets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cloudrec-lite.db")
	rulesDir := t.TempDir()
	writeTestFile(t, filepath.Join(rulesDir, "metadata.json"), `{
		"id": "test.noop",
		"name": "noop",
		"severity": "low",
		"provider": "delta",
		"asset_type": "thing",
		"query": "data.test_noop.risk"
	}`)
	writeTestFile(t, filepath.Join(rulesDir, "policy.rego"), `package test_noop
import rego.v1

default risk := false`)

	provider := &deltaProvider{}
	scanner := NewScanner()
	scanner.RegisterProvider(provider)

	first, err := scanner.ScanContext(ctx, ScanOptions{
		Provider: "delta",
		Account:  "default",
		RulesDir: rulesDir,
		DBPath:   dbPath,
	})
	if err != nil {
		t.Fatalf("first scan returned error: %v", err)
	}
	if first.AddedAssetCount != 2 {
		t.Fatalf("first scan added assets = %d, want 2", first.AddedAssetCount)
	}

	second, err := scanner.ScanContext(ctx, ScanOptions{
		Provider: "delta",
		Account:  "default",
		RulesDir: rulesDir,
		DBPath:   dbPath,
	})
	if err != nil {
		t.Fatalf("second scan returned error: %v", err)
	}
	if second.MissingAssetCount != 1 || second.SeenAssetCount != 1 || second.AddedAssetCount != 0 {
		t.Fatalf("unexpected second scan delta: %+v", second)
	}
}

func TestScannerScanDeltaOnlyMarksSelectedResourceTypesMissing(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cloudrec-lite.db")
	rulesDir := t.TempDir()
	writeTestFile(t, filepath.Join(rulesDir, "metadata.json"), `{
		"id": "test.noop",
		"name": "noop",
		"severity": "low",
		"provider": "delta",
		"asset_type": "thing",
		"query": "data.test_noop.risk"
	}`)
	writeTestFile(t, filepath.Join(rulesDir, "policy.rego"), `package test_noop
import rego.v1

default risk := false`)

	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if _, err := store.UpsertAccount(ctx, model.Account{
		ID:       "default",
		Provider: "delta",
		Name:     "default",
	}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}
	if _, err := store.UpsertAsset(ctx, model.Asset{
		AccountID:    "default",
		Provider:     "delta",
		ResourceType: "other",
		ResourceID:   "other-asset",
		Name:         "other",
	}); err != nil {
		t.Fatalf("upsert existing unrelated asset: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanner := NewScanner()
	scanner.RegisterProvider(&singleAssetProvider{})

	result, err := scanner.ScanContext(ctx, ScanOptions{
		Provider: "delta",
		Account:  "default",
		RulesDir: rulesDir,
		DBPath:   dbPath,
		Config: map[string]string{
			"resource_types": "thing",
		},
	})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if result.MissingAssetCount != 0 {
		t.Fatalf("missing assets = %d, want 0 for unrelated resource type", result.MissingAssetCount)
	}
	if result.AddedAssetCount != 1 {
		t.Fatalf("added assets = %d, want 1", result.AddedAssetCount)
	}
}

type partialProvider struct{}

func (partialProvider) Name() string { return "partial" }

func (partialProvider) ValidateAccount(context.Context, liteprovider.Account) error { return nil }

func (partialProvider) CollectAssets(context.Context, liteprovider.Account) ([]liteprovider.Asset, error) {
	assets := []liteprovider.Asset{{
		ID:        "asset-1",
		Provider:  "partial",
		AccountID: "default",
		Type:      "bucket",
		Name:      "kept",
		Region:    "global",
	}}
	return assets, &liteprovider.PartialCollectionError{
		Assets: assets,
		Failures: []liteprovider.CollectionFailure{{
			ResourceType: "OSS",
			Region:       "cn-hangzhou",
			Message:      "permission denied",
		}},
	}
}

func (partialProvider) Capabilities() liteprovider.Capabilities {
	return liteprovider.Capabilities{AssetTypes: []string{"bucket"}}
}

type linkedProvider struct {
	clientStatus string
	authVersion  int
}

func (p linkedProvider) Name() string { return "linktest" }

func (p linkedProvider) ValidateAccount(context.Context, liteprovider.Account) error { return nil }

func (p linkedProvider) CollectAssets(ctx context.Context, account liteprovider.Account) ([]liteprovider.Asset, error) {
	return []liteprovider.Asset{
		{
			ID:        "ens-1",
			Provider:  "linktest",
			AccountID: account.AccountID,
			Type:      "ENS Instance",
			Name:      "edge-1",
			Properties: map[string]any{
				"Instance": map[string]any{
					"InstanceId": "i-1",
				},
			},
		},
		{
			ID:        "sas-1",
			Provider:  "linktest",
			AccountID: account.AccountID,
			Type:      "Sas",
			Name:      "agent-1",
			Properties: map[string]any{
				"Instance": map[string]any{
					"InstanceId":   "i-1",
					"ClientStatus": p.clientStatus,
					"AuthVersion":  p.authVersion,
				},
			},
		},
	}, nil
}

func (p linkedProvider) Capabilities() liteprovider.Capabilities {
	return liteprovider.Capabilities{AssetTypes: []string{"ENS Instance", "Sas"}}
}

type deltaProvider struct {
	calls int
}

func (p *deltaProvider) Name() string { return "delta" }

func (p *deltaProvider) ValidateAccount(context.Context, liteprovider.Account) error { return nil }

func (p *deltaProvider) CollectAssets(ctx context.Context, account liteprovider.Account) ([]liteprovider.Asset, error) {
	p.calls++
	assets := []liteprovider.Asset{{
		ID:        "asset-1",
		Provider:  "delta",
		AccountID: account.AccountID,
		Type:      "thing",
		Name:      "kept",
	}}
	if p.calls == 1 {
		assets = append(assets, liteprovider.Asset{
			ID:        "asset-2",
			Provider:  "delta",
			AccountID: account.AccountID,
			Type:      "thing",
			Name:      "removed",
		})
	}
	return assets, nil
}

func (p *deltaProvider) Capabilities() liteprovider.Capabilities {
	return liteprovider.Capabilities{AssetTypes: []string{"thing"}}
}

type singleAssetProvider struct{}

func (p *singleAssetProvider) Name() string { return "delta" }

func (p *singleAssetProvider) ValidateAccount(context.Context, liteprovider.Account) error {
	return nil
}

func (p *singleAssetProvider) CollectAssets(ctx context.Context, account liteprovider.Account) ([]liteprovider.Asset, error) {
	return []liteprovider.Asset{{
		ID:        "asset-1",
		Provider:  "delta",
		AccountID: account.AccountID,
		Type:      "thing",
		Name:      "kept",
	}}, nil
}

func (p *singleAssetProvider) Capabilities() liteprovider.Capabilities {
	return liteprovider.Capabilities{AssetTypes: []string{"thing"}}
}

type telemetryProvider struct{}

func (p telemetryProvider) Name() string { return "telemetry" }

func (p telemetryProvider) ValidateAccount(context.Context, liteprovider.Account) error { return nil }

func (p telemetryProvider) CollectAssets(ctx context.Context, account liteprovider.Account) ([]liteprovider.Asset, error) {
	success := collectorstate.StartTask(ctx, "test collector", "bucket", "cn-hangzhou")
	assets := []liteprovider.Asset{{
		ID:        "bucket-1",
		Provider:  "telemetry",
		AccountID: account.AccountID,
		Type:      "bucket",
		Region:    "cn-hangzhou",
		Name:      "bucket-1",
	}}
	success.Done(nil, "", "", len(assets))

	failure := collectorstate.StartTask(ctx, "test collector", "queue", "cn-nanjing")
	failure.Done(context.DeadlineExceeded, "unsupported_region", "queue endpoint no such host", 0)
	collectorstate.ObserveFailure(ctx, "queue", "cn-nanjing", "unsupported_region", "queue endpoint no such host")

	return assets, &liteprovider.PartialCollectionError{
		Assets: assets,
		Failures: []liteprovider.CollectionFailure{{
			ResourceType: "queue",
			Region:       "cn-nanjing",
			Category:     "unsupported_region",
			Message:      "queue endpoint no such host",
		}},
	}
}

func (p telemetryProvider) Capabilities() liteprovider.Capabilities {
	return liteprovider.Capabilities{AssetTypes: []string{"bucket"}}
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func intFromSummary(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return 0
	}
}
