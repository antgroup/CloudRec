package rule

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAlicloudReleaseQualityGate(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "rules", "alicloud")
	samplesDir := filepath.Join("..", "..", "samples", "alicloud")
	ledgerPath := filepath.Join(rulesDir, "review-ledger.json")

	coverage, err := AnalyzeCoverage(CoverageOptions{
		RulesDir:         rulesDir,
		Provider:         "alicloud",
		SamplesDir:       samplesDir,
		ReviewLedgerPath: ledgerPath,
	})
	if err != nil {
		t.Fatalf("AnalyzeCoverage() error = %v", err)
	}
	if coverage.Totals.NeedsReview != 0 || coverage.Totals.NeedsOfficialDocs != 0 || coverage.Totals.Blocked != 0 || coverage.Totals.NeedsLogicChange != 0 {
		t.Fatalf("release review gate failed: %+v", coverage.Totals)
	}
	if coverage.Totals.MissingRemediation != 0 {
		t.Fatalf("release remediation gate failed: %+v", coverage.Totals)
	}
	if coverage.Totals.MissingDataRefs != 0 {
		t.Fatalf("release relation data gate failed: %+v", coverage.Totals)
	}
	if coverage.Totals.MissingSampleRefs != 0 || coverage.Totals.MissingSampleGroups != 0 {
		t.Fatalf("release sample coverage gate failed: %+v", coverage.Totals)
	}

	validation, err := AnalyzeValidation(context.Background(), ValidationOptions{
		RulesDir:   rulesDir,
		Provider:   "alicloud",
		SamplesDir: samplesDir,
	})
	if err != nil {
		t.Fatalf("AnalyzeValidation() error = %v", err)
	}
	if validation.Totals.FailedExamples != 0 || validation.Totals.NeedsLogicChange != 0 || validation.Totals.MissingInputRefs != 0 || validation.Totals.MissingSampleRefs != 0 {
		t.Fatalf("release validation gate failed: %+v", validation.Totals)
	}
}
