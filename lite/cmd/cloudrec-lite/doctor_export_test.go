package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antgroup/CloudRec/lite/internal/core"
	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/storage"
)

func TestRunDoctorJSONRedactsCredentials(t *testing.T) {
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
	t.Setenv("ALIBABA_CLOUD_REGION", "")

	dir := t.TempDir()
	writeCLIRulePack(t, dir, "oss-doctor", `{
		"id": "alicloud.oss.doctor",
		"name": "OSS doctor",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `{"bucket": "demo"}`)
	envFile := filepath.Join(t.TempDir(), ".env.local")
	writeMainTestFile(t, envFile, "ALIBABA_CLOUD_ACCESS_KEY_ID=unit-ak\nALIBABA_CLOUD_ACCESS_KEY_SECRET=unit-sk\nALIBABA_CLOUD_REGION=cn-hangzhou\n")

	var out bytes.Buffer
	err := runDoctorWithWriter([]string{
		"--provider", "alicloud",
		"--account", "unit-account",
		"--rules", dir,
		"--db", filepath.Join(t.TempDir(), "cloudrec.db"),
		"--env-file", envFile,
		"--credential-source", "env",
		"--format", "json",
	}, &out)
	if err != nil {
		t.Fatalf("doctor returned error: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "unit-ak") || strings.Contains(out.String(), "unit-sk") {
		t.Fatalf("doctor output leaked credential material:\n%s", out.String())
	}

	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor report: %v\n%s", err, out.String())
	}
	if report.Summary.Failed != 0 {
		t.Fatalf("unexpected failed doctor checks: %+v", report)
	}
	if !strings.Contains(out.String(), "access key id present") || !strings.Contains(out.String(), "access key secret present") {
		t.Fatalf("doctor output should confirm credential presence without values:\n%s", out.String())
	}
}

func TestRunDoctorReturnsFailureForMissingRules(t *testing.T) {
	var out bytes.Buffer
	err := runDoctorWithWriter([]string{
		"--provider", "mock",
		"--rules", filepath.Join(t.TempDir(), "missing"),
		"--db", filepath.Join(t.TempDir(), "cloudrec.db"),
		"--env-file", "",
		"--format", "json",
	}, &out)
	if !errors.Is(err, errDoctorFailed) {
		t.Fatalf("expected doctor failed error, got %v\n%s", err, out.String())
	}

	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor report: %v\n%s", err, out.String())
	}
	if report.Summary.Failed == 0 {
		t.Fatalf("expected failed doctor check: %+v", report)
	}
}

func TestBuildDoctorReportUsesDefaultDBPath(t *testing.T) {
	report := buildDoctorReport(doctorOptions{
		Provider: "mock",
		Account:  "unit",
		RulesDir: t.TempDir(),
	})
	if report.DBPath != core.DefaultDBPath() {
		t.Fatalf("DBPath = %q, want %q", report.DBPath, core.DefaultDBPath())
	}
}

func TestBuildDoctorReportChecksLedgerSamplesAndTempSpace(t *testing.T) {
	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules", "mock")
	samplesDir := filepath.Join(root, "samples", "mock")
	writeCLIRulePack(t, rulesDir, "asset-rule", `{
		"id": "mock.asset.rule",
		"name": "Mock Asset Rule",
		"severity": "low",
		"provider": "mock",
		"asset_type": "mock_asset"
	}`, `{"Name":"demo"}`)
	writeMainTestFile(t, filepath.Join(rulesDir, "review-ledger.json"), `{"rules":[{"id":"mock.asset.rule","review_status":"official_reviewed"}]}`)
	if err := os.MkdirAll(samplesDir, 0o755); err != nil {
		t.Fatalf("mkdir samples: %v", err)
	}
	writeMainTestFile(t, filepath.Join(samplesDir, "mock_asset.json"), `{"resource_type":"mock_asset","input":{"Name":"demo"}}`)

	report := buildDoctorReport(doctorOptions{
		Provider: "mock",
		Account:  "unit",
		RulesDir: rulesDir,
		DBPath:   filepath.Join(root, "cloudrec.db"),
	})

	if got := doctorCheckByName(report.Checks, "review_ledger"); got.Status != doctorStatusPass {
		t.Fatalf("review ledger check = %+v", got)
	}
	if got := doctorCheckByName(report.Checks, "samples"); got.Status != doctorStatusPass {
		t.Fatalf("samples check = %+v", got)
	}
	if got := doctorCheckByName(report.Checks, "temp_space"); got.Status != doctorStatusPass {
		t.Fatalf("temp space check = %+v", got)
	}
}

func TestRunExportRemediationMarkdownRedactsEvidence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cloudrec.db")
	seedRemediationExportDB(t, dbPath)

	var out bytes.Buffer
	err := runExportRemediationWithWriter([]string{
		"--db", dbPath,
		"--format", "markdown",
	}, &out)
	if err != nil {
		t.Fatalf("export remediation returned error: %v", err)
	}
	body := out.String()
	for _, want := range []string{"CloudRec Lite Remediation Notes", "Public OSS bucket", "Disable public access", "[redacted]"} {
		if !strings.Contains(body, want) {
			t.Fatalf("export output missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "unit-secret-value") {
		t.Fatalf("export output leaked secret evidence:\n%s", body)
	}
}

func doctorCheckByName(checks []doctorCheck, name string) doctorCheck {
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	return doctorCheck{Name: name, Status: "missing"}
}

func TestRunExportRemediationHydratesMissingAdviceFromRules(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cloudrec.db")
	seedRemediationExportDBWithoutAdvice(t, dbPath)
	rulesDir := t.TempDir()
	writeCLIRulePack(t, rulesDir, "account-advice", `{
		"id": "alicloud.account.missing_advice",
		"name": "Account advice",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "account",
		"legacy": {
			"advice": "删除主账号 AK，改用 RAM User 或 Role。"
		}
	}`, `{"risk":true}`)

	var out bytes.Buffer
	err := runExportRemediationWithWriter([]string{
		"--db", dbPath,
		"--rules", rulesDir,
		"--format", "markdown",
	}, &out)
	if err != nil {
		t.Fatalf("export remediation returned error: %v", err)
	}
	if !strings.Contains(out.String(), "删除主账号 AK") {
		t.Fatalf("export did not hydrate rule advice:\n%s", out.String())
	}
}

func TestRunExportRemediationRequiresExistingDatabase(t *testing.T) {
	var out bytes.Buffer
	err := runExportRemediationWithWriter([]string{
		"--db", filepath.Join(t.TempDir(), "missing.db"),
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing database error, got %v", err)
	}
}

func seedRemediationExportDBWithoutAdvice(t *testing.T, dbPath string) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if _, err := store.UpsertAccount(ctx, model.Account{ID: "account-1", Provider: "alicloud", Name: "account-1"}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}
	run, err := store.CreateScanRun(ctx, model.ScanRun{AccountID: "account-1", Provider: "alicloud"})
	if err != nil {
		t.Fatalf("create scan run: %v", err)
	}
	asset, err := store.UpsertAsset(ctx, model.Asset{
		AccountID:    "account-1",
		Provider:     "alicloud",
		ResourceType: "account",
		ResourceID:   "account-1",
		Name:         "account-1",
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	if _, err := store.UpsertFinding(ctx, model.Finding{
		ScanRunID: run.ID,
		AccountID: "account-1",
		AssetID:   asset.ID,
		RuleID:    "alicloud.account.missing_advice",
		Title:     "Missing advice",
		Severity:  model.SeverityHigh,
		Status:    model.FindingStatusOpen,
		Message:   "Missing remediation in DB.",
	}); err != nil {
		t.Fatalf("upsert finding: %v", err)
	}
}

func seedRemediationExportDB(t *testing.T, dbPath string) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if _, err := store.UpsertAccount(ctx, model.Account{
		ID:       "account-1",
		Provider: "alicloud",
		Name:     "account-1",
	}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}
	run, err := store.CreateScanRun(ctx, model.ScanRun{
		AccountID: "account-1",
		Provider:  "alicloud",
	})
	if err != nil {
		t.Fatalf("create scan run: %v", err)
	}
	asset, err := store.UpsertAsset(ctx, model.Asset{
		AccountID:    "account-1",
		Provider:     "alicloud",
		ResourceType: "OSS",
		ResourceID:   "bucket-1",
		Region:       "cn-hangzhou",
		Name:         "bucket-1",
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	if _, err := store.UpsertFinding(ctx, model.Finding{
		ScanRunID:   run.ID,
		AccountID:   "account-1",
		AssetID:     asset.ID,
		RuleID:      "alicloud.oss.public",
		Title:       "Public OSS bucket",
		Severity:    model.SeverityHigh,
		Status:      model.FindingStatusOpen,
		Message:     "Bucket allows public access.",
		Evidence:    json.RawMessage(`{"AccessKeySecret":"unit-secret-value","public":true}`),
		Remediation: "Disable public access.",
	}); err != nil {
		t.Fatalf("upsert finding: %v", err)
	}
	if _, err := store.FinishScanRun(ctx, run.ID, model.ScanRunStatusSucceeded, json.RawMessage(`{"assets":1,"findings":1}`)); err != nil {
		t.Fatalf("finish scan run: %v", err)
	}
}
