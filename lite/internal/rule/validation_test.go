package rule

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeValidationRunsExamplesAndTracksMissingRefs(t *testing.T) {
	dir := t.TempDir()
	writeValidationPack(t, dir, "oss-valid", `{
		"id": "alicloud.oss.valid",
		"name": "OSS valid",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `[
		{"name":"public","input":{"provider":"alicloud","attributes":{"public":true}},"want_findings":1},
		{"name":"private","input":{"provider":"alicloud","attributes":{"public":false}},"want_findings":0}
	]`, `package oss_valid
import rego.v1
findings contains finding if {
	input.attributes.public == true
	finding := {"title": "public"}
}`)
	writeValidationPack(t, dir, "oss-mismatch", `{
		"id": "alicloud.oss.mismatch",
		"name": "OSS mismatch",
		"severity": "medium",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `[{"name":"mismatch","input":{"provider":"alicloud","enabled":true},"want_findings":0}]`, `package oss_mismatch
import rego.v1
findings contains finding if {
	input.enabled == true
	finding := {"title": "enabled"}
}`)
	writeValidationPack(t, dir, "oss-missing-ref", `{
		"id": "alicloud.oss.missing_ref",
		"name": "OSS missing ref",
		"severity": "low",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `[{"name":"unknown","input":{"provider":"alicloud"},"want_findings":-1}]`, `package oss_missing_ref
import rego.v1
default risk := false
risk if input.missing.field == "x"
`)

	report, err := AnalyzeValidation(context.Background(), ValidationOptions{RulesDir: dir, Provider: "alicloud"})
	if err != nil {
		t.Fatalf("AnalyzeValidation() error = %v", err)
	}
	if report.Totals.TotalRules != 3 || report.Totals.Examples != 4 || report.Totals.PassedExamples != 3 || report.Totals.FailedExamples != 1 {
		t.Fatalf("unexpected validation totals: %+v", report.Totals)
	}
	if report.Totals.NeedsLogicChange != 1 || report.Totals.FixtureOnly != 2 {
		t.Fatalf("unexpected validation statuses: %+v", report.Totals)
	}
	var missingRef RuleValidation
	for _, row := range report.Rules {
		if row.ID == "alicloud.oss.missing_ref" {
			missingRef = row
		}
	}
	if len(missingRef.MissingFixtureRefs) != 1 || missingRef.MissingFixtureRefs[0] != "missing.field" {
		t.Fatalf("missing fixture refs = %#v", missingRef.MissingFixtureRefs)
	}
}

func TestAnalyzeValidationUsesRealFieldSamples(t *testing.T) {
	dir := t.TempDir()
	samples := t.TempDir()
	writeValidationPack(t, dir, "oss-valid", `{
		"id": "alicloud.oss.valid",
		"name": "OSS valid",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `[{"name":"public","input":{"attributes":{"public":true}},"want_findings":1}]`, `package oss_valid
import rego.v1
findings contains finding if {
	input.attributes.public == true
	finding := {"title": "public"}
}`)
	writeValidationFile(t, samples, "oss-real.json", `{
		"resource_type": "OSS",
		"input": {"attributes": {"public": false, "extra": true}}
	}`)

	report, err := AnalyzeValidation(context.Background(), ValidationOptions{
		RulesDir:   dir,
		Provider:   "alicloud",
		SamplesDir: samples,
	})
	if err != nil {
		t.Fatalf("AnalyzeValidation() error = %v", err)
	}
	if report.Totals.RealFieldVerified != 1 || report.Totals.FixtureOnly != 0 || report.Totals.FieldSamples != 1 {
		t.Fatalf("unexpected validation totals with samples: %+v", report.Totals)
	}
	if got := report.Rules[0].ValidationStatus; got != ValidationStatusRealField {
		t.Fatalf("validation status = %q, want %q", got, ValidationStatusRealField)
	}
}

func TestRenderValidationJSONAndTable(t *testing.T) {
	report := ValidationReport{
		Provider: "alicloud",
		Totals: ValidationTotals{
			TotalRules:     1,
			FixtureOnly:    1,
			Examples:       1,
			PassedExamples: 1,
		},
		Rules: []RuleValidation{{
			ID:               "rule-1",
			Provider:         "alicloud",
			ResourceType:     "OSS",
			ValidationStatus: ValidationStatusFixtureOnly,
			Examples:         1,
			PassedExamples:   1,
		}},
	}
	var jsonOut bytes.Buffer
	if err := RenderValidation(&jsonOut, report, ValidationFormatJSON); err != nil {
		t.Fatalf("RenderValidation(json) error = %v", err)
	}
	if !strings.Contains(jsonOut.String(), `"validation_status": "fixture_only"`) {
		t.Fatalf("json output missing validation status:\n%s", jsonOut.String())
	}

	var tableOut bytes.Buffer
	if err := RenderValidation(&tableOut, report, ValidationFormatTable); err != nil {
		t.Fatalf("RenderValidation(table) error = %v", err)
	}
	for _, want := range []string{"Provider", "rule-1", "Totals"} {
		if !strings.Contains(tableOut.String(), want) {
			t.Fatalf("table output missing %q:\n%s", want, tableOut.String())
		}
	}
}

func writeValidationPack(t *testing.T, root string, name string, metadata string, examples string, policy string) {
	t.Helper()
	writeValidationFile(t, root, name+"/metadata.json", metadata)
	writeValidationFile(t, root, name+"/policy.rego", policy)
	if examples != "" {
		writeValidationFile(t, root, name+"/examples.json", examples)
	}
}

func writeValidationFile(t *testing.T, root string, relative string, content string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
