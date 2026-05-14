package rule

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeCoverageAggregatesRules(t *testing.T) {
	dir := t.TempDir()
	writeCoveragePack(t, dir, "oss-active", `{
		"id": "alicloud.oss.active",
		"name": "OSS active",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "oss"
	}`, `{"bucket": "demo"}`, "")
	writeCoveragePack(t, dir, "oss-disabled", `{
		"id": "alicloud.oss.disabled",
		"name": "OSS disabled",
		"severity": "low",
		"provider": "ALI_CLOUD",
		"asset_type": "OSS",
		"disabled": true
	}`, `{"bucket": "demo"}`, "")
	writeCoveragePack(t, dir, "ecs-missing-data", `{
		"id": "alicloud.ecs.missing_data",
		"name": "ECS missing data",
		"severity": "medium",
		"provider": "alicloud",
		"asset_type": "ecs"
	}`, "", `["missing-ref"]`)

	report, err := AnalyzeCoverage(CoverageOptions{
		RulesDir: dir,
		Provider: "alicloud",
		Catalog: []CoverageCatalogSpec{
			{Type: "OSS", Group: "STORE", Dimension: "global"},
			{Type: "ECS", Group: "COMPUTE", Dimension: "regional"},
		},
		NativeAdapters: map[string]bool{"OSS": true},
	})
	if err != nil {
		t.Fatalf("AnalyzeCoverage() error = %v", err)
	}

	if report.Totals.ResourceTypes != 2 || report.Totals.TotalRules != 3 || report.Totals.WithExamples != 2 || report.Totals.MissingDataRefs != 1 || report.Totals.Disabled != 1 {
		t.Fatalf("totals = %#v", report.Totals)
	}
	if got := report.Resources[0]; got.ResourceType != "ECS" || got.TotalRules != 1 || !got.ProviderSupported || got.NativeAdapter {
		t.Fatalf("ECS row = %#v", got)
	}
	if got := report.Resources[1]; got.ResourceType != "OSS" || got.TotalRules != 2 || got.WithExamples != 2 || got.Disabled != 1 || !got.NativeAdapter {
		t.Fatalf("OSS row = %#v", got)
	}
}

func TestAnalyzeCoverageAddsReviewAndFieldQuality(t *testing.T) {
	dir := t.TempDir()
	samples := t.TempDir()
	ledger := filepath.Join(dir, "review-ledger.json")
	writeCoveragePack(t, dir, "oss-reviewed", `{
		"id": "alicloud.oss.reviewed",
		"name": "OSS reviewed",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS",
		"advice": "Restrict bucket ACL."
	}`, `{"BucketInfo":{"ACL":"public-read"}}`, "")
	writeRuleFile(t, dir, "oss-reviewed/policy.rego", `package oss_reviewed
import rego.v1
default risk := false
risk if input.BucketInfo.ACL == "public-read"
`)
	writeRuleFile(t, samples, "oss.json", `{"resource_type":"OSS","input":{"BucketInfo":{"ACL":"private"}}}`)
	writeRuleFile(t, dir, "review-ledger.json", `{"rules":[{"id":"alicloud.oss.reviewed","review_status":"official_reviewed"}]}`)

	report, err := AnalyzeCoverage(CoverageOptions{
		RulesDir:         dir,
		Provider:         "alicloud",
		SamplesDir:       samples,
		ReviewLedgerPath: ledger,
		Catalog:          []CoverageCatalogSpec{{Type: "OSS", Group: "STORE", Dimension: "global"}},
		NativeAdapters:   map[string]bool{"OSS": true},
	})
	if err != nil {
		t.Fatalf("AnalyzeCoverage() error = %v", err)
	}
	if report.Totals.OfficialReviewed != 1 || report.Totals.VerifiedResources != 1 || report.Totals.MissingSampleRefs != 0 {
		t.Fatalf("unexpected totals: %+v", report.Totals)
	}
	if got := report.Resources[0]; got.CollectorFieldStatus != "verified" || got.FieldSamples != 1 || got.OfficialReviewed != 1 {
		t.Fatalf("unexpected resource quality: %+v", got)
	}
}

func TestRenderCoverageJSONAndTable(t *testing.T) {
	report := CoverageReport{
		Provider: "alicloud",
		Totals: CoverageTotals{
			ResourceTypes:   1,
			TotalRules:      2,
			WithExamples:    1,
			MissingDataRefs: 0,
			Disabled:        1,
		},
		Resources: []ResourceCoverage{{
			Provider:          "alicloud",
			ResourceType:      "OSS",
			Normalized:        "oss",
			TotalRules:        2,
			WithExamples:      1,
			Disabled:          1,
			ProviderSupported: true,
			NativeAdapter:     true,
			CatalogType:       "OSS",
			Group:             "STORE",
			Dimension:         "global",
		}},
	}

	var jsonOut bytes.Buffer
	if err := RenderCoverage(&jsonOut, report, CoverageFormatJSON); err != nil {
		t.Fatalf("RenderCoverage(json) error = %v", err)
	}
	wantJSON := `{
  "provider": "alicloud",
  "totals": {
    "resource_types": 1,
    "total_rules": 2,
    "with_examples": 1,
    "missing_data_refs": 0,
    "disabled": 1
  },
  "resources": [
    {
      "provider": "alicloud",
      "resource_type": "OSS",
      "normalized": "oss",
      "total_rules": 2,
      "with_examples": 1,
      "missing_data_refs": 0,
      "disabled": 1,
      "provider_supported": true,
      "native_adapter": true,
      "catalog_type": "OSS",
      "group": "STORE",
      "dimension": "global"
    }
  ]
}
`
	if jsonOut.String() != wantJSON {
		t.Fatalf("json output mismatch\nwant:\n%s\ngot:\n%s", wantJSON, jsonOut.String())
	}

	var tableOut bytes.Buffer
	if err := RenderCoverage(&tableOut, report, CoverageFormatTable); err != nil {
		t.Fatalf("RenderCoverage(table) error = %v", err)
	}
	for _, want := range []string{"Provider", "Resource Type", "OSS", "Totals", "1 resource types"} {
		if !strings.Contains(tableOut.String(), want) {
			t.Fatalf("table output missing %q:\n%s", want, tableOut.String())
		}
	}
}

func writeCoveragePack(t *testing.T, root string, name string, metadata string, input string, relation string) {
	t.Helper()

	writeRuleFile(t, root, name+"/metadata.json", metadata)
	writeRuleFile(t, root, name+"/policy.rego", "package "+strings.ReplaceAll(name, "-", "_")+"\nimport rego.v1\ndefault risk := false\n")
	if input != "" {
		writeRuleFile(t, root, name+"/input.json", input)
	}
	if relation != "" {
		writeRuleFile(t, root, name+"/relation.json", relation)
	}
}
