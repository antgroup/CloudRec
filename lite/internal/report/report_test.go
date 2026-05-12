package report

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/antgroup/CloudRec/lite/internal/core"
)

func TestRenderScanResultText(t *testing.T) {
	var out bytes.Buffer
	result := core.ScanResult{
		Provider:           "mock",
		Account:            "default",
		RuleCount:          2,
		AssetCount:         3,
		AddedAssetCount:    3,
		FindingCount:       1,
		EvaluatedRuleCount: 3,
		SkippedRuleCount:   3,
		DryRun:             true,
		ScanRunID:          "scan-001",
	}

	err := RenderScanResult(&out, result, FormatText)
	if err != nil {
		t.Fatalf("RenderScanResult returned error: %v", err)
	}

	want := "scan completed: provider=mock account=default assets=3 addedAssets=3 updatedAssets=0 missingAssets=0 seenAssets=0 findings=1 rules=2 evaluatedRules=3 skippedRules=3 collectionFailures=0 collectionTasks=0 skippedTasks=0 dryRun=true\n"
	if got := out.String(); got != want {
		t.Fatalf("text report = %q, want %q", got, want)
	}
}

func TestRenderScanResultDefaultsToText(t *testing.T) {
	var out bytes.Buffer
	result := core.ScanResult{
		Provider:     "mock",
		Account:      "default",
		AssetCount:   3,
		FindingCount: 1,
		DryRun:       true,
	}

	err := RenderScanResult(&out, result, "")
	if err != nil {
		t.Fatalf("RenderScanResult returned error: %v", err)
	}

	want := "scan completed: provider=mock account=default assets=3 addedAssets=0 updatedAssets=0 missingAssets=0 seenAssets=0 findings=1 rules=0 evaluatedRules=0 skippedRules=0 collectionFailures=0 collectionTasks=0 skippedTasks=0 dryRun=true\n"
	if got := out.String(); got != want {
		t.Fatalf("default report = %q, want %q", got, want)
	}
}

func TestRenderScanResultJSON(t *testing.T) {
	var out bytes.Buffer
	result := core.ScanResult{
		Provider:               "mock",
		Account:                "default",
		RuleCount:              2,
		AssetCount:             3,
		AddedAssetCount:        2,
		UpdatedAssetCount:      1,
		SeenAssetCount:         3,
		FindingCount:           1,
		EvaluatedRuleCount:     3,
		SkippedRuleCount:       3,
		CollectionFailureCount: 1,
		DryRun:                 false,
		ScanRunID:              "scan-001",
	}

	err := RenderScanResult(&out, result, " JSON ")
	if err != nil {
		t.Fatalf("RenderScanResult returned error: %v", err)
	}

	want := `{
  "provider": "mock",
  "account": "default",
  "rule_count": 2,
  "asset_count": 3,
  "added_asset_count": 2,
  "updated_asset_count": 1,
  "missing_asset_count": 0,
  "seen_asset_count": 3,
  "finding_count": 1,
  "evaluated_rule_count": 3,
  "skipped_rule_count": 3,
  "collection_failure_count": 1,
  "dry_run": false,
  "scan_run_id": "scan-001"
}
`
	if got := out.String(); got != want {
		t.Fatalf("json report = %q, want %q", got, want)
	}
}

func TestRenderScanResultJSONOmitsEmptyScanRunID(t *testing.T) {
	var out bytes.Buffer
	result := core.ScanResult{
		Provider:     "mock",
		Account:      "default",
		RuleCount:    2,
		AssetCount:   3,
		FindingCount: 1,
		DryRun:       true,
	}

	err := RenderScanResult(&out, result, FormatJSON)
	if err != nil {
		t.Fatalf("RenderScanResult returned error: %v", err)
	}

	want := `{
  "provider": "mock",
  "account": "default",
  "rule_count": 2,
  "asset_count": 3,
  "added_asset_count": 0,
  "updated_asset_count": 0,
  "missing_asset_count": 0,
  "seen_asset_count": 0,
  "finding_count": 1,
  "evaluated_rule_count": 0,
  "skipped_rule_count": 0,
  "collection_failure_count": 0,
  "dry_run": true
}
`
	if got := out.String(); got != want {
		t.Fatalf("json report = %q, want %q", got, want)
	}
}

func TestRenderScanResultRequiresWriter(t *testing.T) {
	err := RenderScanResult(nil, core.ScanResult{}, FormatText)
	if err == nil {
		t.Fatal("expected nil writer error")
	}
}

func TestRenderScanResultUnsupportedFormat(t *testing.T) {
	err := RenderScanResult(io.Discard, core.ScanResult{}, "yaml")
	if err == nil {
		t.Fatal("expected unsupported format error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRenderScanResultPropagatesWriterError(t *testing.T) {
	err := RenderScanResult(failingWriter{}, core.ScanResult{}, FormatText)
	if err == nil {
		t.Fatal("expected writer error")
	}
}
