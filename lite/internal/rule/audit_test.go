package rule

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeAuditBuildsRuleLedger(t *testing.T) {
	dir := t.TempDir()
	writeAuditRulePack(t, dir, "oss-public", `{
		"id": "ALI_CLOUD_OSS_PUBLIC",
		"name": "OSS public policy",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `package test
import rego.v1
default risk := false
risk if {
  input.BucketPolicyStatus.IsPublic
  input.BucketInfo.ACL == "public-read"
}`)

	report, err := AnalyzeAudit(AuditOptions{RulesDir: dir, Provider: "alicloud"})
	if err != nil {
		t.Fatalf("analyze audit: %v", err)
	}
	if report.Totals.TotalRules != 1 || report.Totals.NeedsReview != 1 || report.Totals.WithOfficialDocs != 1 {
		t.Fatalf("unexpected audit totals: %+v", report.Totals)
	}
	item := report.Rules[0]
	if item.ID != "ALI_CLOUD_OSS_PUBLIC" || item.ResourceType != "OSS" || item.ReviewStatus != AuditStatusNeedsReview {
		t.Fatalf("unexpected audit item: %+v", item)
	}
	if len(item.PolicySHA256) != 64 {
		t.Fatalf("policy hash length = %d, want 64", len(item.PolicySHA256))
	}
	if !stringSliceContains(item.InputReferences, "BucketPolicyStatus.IsPublic") || !stringSliceContains(item.InputReferences, "BucketInfo.ACL") {
		t.Fatalf("unexpected input refs: %+v", item.InputReferences)
	}
	if !strings.Contains(item.LogicSummary, "2_input_refs") {
		t.Fatalf("unexpected logic summary: %q", item.LogicSummary)
	}

	var table bytes.Buffer
	if err := RenderAudit(&table, report, AuditFormatTable); err != nil {
		t.Fatalf("render audit table: %v", err)
	}
	for _, want := range []string{"Provider", "ALI_CLOUD_OSS_PUBLIC", "needs_official_review", "Totals"} {
		if !strings.Contains(table.String(), want) {
			t.Fatalf("audit table missing %q:\n%s", want, table.String())
		}
	}
}

func TestAnalyzeAuditMarksMissingOfficialDocs(t *testing.T) {
	dir := t.TempDir()
	writeAuditRulePack(t, dir, "unknown", `{
		"id": "ALI_CLOUD_UNKNOWN",
		"name": "Unknown product",
		"severity": "medium",
		"provider": "alicloud",
		"asset_type": "Unknown Product"
	}`, `package test
import rego.v1
default risk := false
risk if { input.Enabled == false }`)

	report, err := AnalyzeAudit(AuditOptions{RulesDir: dir, Provider: "alicloud"})
	if err != nil {
		t.Fatalf("analyze audit: %v", err)
	}
	if report.Totals.NeedsOfficialDocs != 1 {
		t.Fatalf("expected missing official docs, got %+v", report.Totals)
	}
	if report.Rules[0].ReviewStatus != AuditStatusNeedsOfficialDocs {
		t.Fatalf("unexpected status: %+v", report.Rules[0])
	}
}

func TestAnalyzeAuditMergesReviewLedgerAndRemediation(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "review-ledger.json")
	writeAuditRulePack(t, dir, "oss-reviewed", `{
		"id": "ALI_CLOUD_OSS_REVIEWED",
		"name": "OSS reviewed",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS",
		"advice": "Restrict bucket access."
	}`, `package test
import rego.v1
default risk := false
risk if input.BucketInfo.ACL == "public-read"`)
	if err := os.WriteFile(ledger, []byte(`{
		"rules": [{
			"id": "ALI_CLOUD_OSS_REVIEWED",
			"review_status": "official_reviewed",
			"reviewed_by": "security-review",
			"reviewed_at": "2026-05-05",
			"current_logic": "checks public bucket ACL",
			"official_behavior": "OSS ACL public-read allows anonymous read unless blocked",
			"test_fixture": "oss-reviewed/input.json",
			"official_docs": [{"title":"OSS ACL","url":"https://www.alibabacloud.com/help/en/oss/"}]
		}]
	}`), 0o644); err != nil {
		t.Fatalf("write ledger: %v", err)
	}

	report, err := AnalyzeAudit(AuditOptions{RulesDir: dir, Provider: "alicloud", ReviewLedgerPath: ledger})
	if err != nil {
		t.Fatalf("analyze audit: %v", err)
	}
	if report.Totals.OfficialReviewed != 1 || report.Totals.WithRemediation != 1 || report.Totals.MissingRemediation != 0 {
		t.Fatalf("unexpected totals: %+v", report.Totals)
	}
	item := report.Rules[0]
	if item.ReviewStatus != AuditStatusOfficialReviewed || item.CurrentLogic == "" || item.TestFixture == "" {
		t.Fatalf("ledger was not merged: %+v", item)
	}
	if !item.HasRemediation || item.RemediationSource != "metadata.advice" {
		t.Fatalf("remediation not detected: %+v", item)
	}
}

func TestAnalyzeAuditAllowsMissingReviewLedgerSeed(t *testing.T) {
	dir := t.TempDir()
	writeAuditRulePack(t, dir, "oss-seed", `{
		"id": "ALI_CLOUD_OSS_SEED",
		"name": "OSS seed",
		"severity": "medium",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `package test
import rego.v1
default risk := false
risk if input.BucketInfo.ACL == "public-read"`)

	report, err := AnalyzeAudit(AuditOptions{
		RulesDir:         dir,
		Provider:         "alicloud",
		ReviewLedgerPath: filepath.Join(dir, "review-ledger.json"),
	})
	if err != nil {
		t.Fatalf("analyze audit with missing ledger seed: %v", err)
	}
	if report.Totals.TotalRules != 1 || report.Rules[0].ReviewStatus != AuditStatusNeedsReview {
		t.Fatalf("unexpected report for missing ledger seed: %+v", report)
	}
}

func writeAuditRulePack(t *testing.T, root string, name string, metadata string, policy string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", dir, err)
	}
	files := map[string]string{
		"metadata.json": metadata,
		"policy.rego":   policy,
	}
	for filename, content := range files {
		if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", filename, err)
		}
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
