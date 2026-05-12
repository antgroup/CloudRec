package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antgroup/CloudRec/lite/internal/core"
)

func TestRunVersion(t *testing.T) {
	if version == "" || version == "0.0.0-dev" {
		t.Fatalf("version = %q, want release-series development version", version)
	}
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version returned error: %v", err)
	}
}

func TestRunScanDryRun(t *testing.T) {
	err := run([]string{"scan", "--provider", "mock", "--account", "test", "--dry-run=true"})
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
}

func TestRunRulesCoverageJSONAndTable(t *testing.T) {
	dir := t.TempDir()
	writeCLIRulePack(t, dir, "oss", `{
		"id": "alicloud.oss.cli",
		"name": "OSS CLI",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "oss"
	}`, `{"bucket": "demo"}`)

	var jsonOut bytes.Buffer
	if err := runRulesCoverageWithWriter([]string{"--rules", dir, "--provider", "alicloud", "--format", "json"}, &jsonOut); err != nil {
		t.Fatalf("rules coverage json returned error: %v", err)
	}
	for _, want := range []string{`"provider": "alicloud"`, `"resource_type": "OSS"`, `"provider_supported": true`, `"native_adapter": true`} {
		if !strings.Contains(jsonOut.String(), want) {
			t.Fatalf("json output missing %q:\n%s", want, jsonOut.String())
		}
	}

	var tableOut bytes.Buffer
	if err := runRulesCoverageWithWriter([]string{"--rules", dir, "--provider", "alicloud", "--format", "table"}, &tableOut); err != nil {
		t.Fatalf("rules coverage table returned error: %v", err)
	}
	for _, want := range []string{"Provider", "OSS", "Totals"} {
		if !strings.Contains(tableOut.String(), want) {
			t.Fatalf("table output missing %q:\n%s", want, tableOut.String())
		}
	}
}

func TestRunRulesAuditJSONAndTable(t *testing.T) {
	dir := t.TempDir()
	writeCLIRulePack(t, dir, "oss-audit", `{
		"id": "alicloud.oss.audit",
		"name": "OSS audit",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `{"bucket": "demo"}`)

	var jsonOut bytes.Buffer
	if err := runRulesAuditWithWriter([]string{"--rules", dir, "--provider", "alicloud", "--format", "json"}, &jsonOut); err != nil {
		t.Fatalf("rules audit json returned error: %v", err)
	}
	for _, want := range []string{`"provider": "alicloud"`, `"id": "alicloud.oss.audit"`, `"review_status": "needs_official_review"`, `"policy_sha256"`} {
		if !strings.Contains(jsonOut.String(), want) {
			t.Fatalf("json output missing %q:\n%s", want, jsonOut.String())
		}
	}

	var tableOut bytes.Buffer
	if err := runRulesAuditWithWriter([]string{"--rules", dir, "--provider", "alicloud", "--format", "table"}, &tableOut); err != nil {
		t.Fatalf("rules audit table returned error: %v", err)
	}
	for _, want := range []string{"Provider", "alicloud.oss.audit", "Totals"} {
		if !strings.Contains(tableOut.String(), want) {
			t.Fatalf("table output missing %q:\n%s", want, tableOut.String())
		}
	}
}

func TestRunRulesValidateJSONAndTable(t *testing.T) {
	dir := t.TempDir()
	writeCLIRulePack(t, dir, "oss-validate", `{
		"id": "alicloud.oss.validate",
		"name": "OSS validate",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`, `{"public": true}`)

	var jsonOut bytes.Buffer
	if err := runRulesValidateWithWriter([]string{"--rules", dir, "--provider", "alicloud", "--format", "json"}, &jsonOut); err != nil {
		t.Fatalf("rules validate json returned error: %v", err)
	}
	for _, want := range []string{`"provider": "alicloud"`, `"id": "alicloud.oss.validate"`, `"validation_status": "fixture_only"`} {
		if !strings.Contains(jsonOut.String(), want) {
			t.Fatalf("json output missing %q:\n%s", want, jsonOut.String())
		}
	}

	var tableOut bytes.Buffer
	if err := runRulesValidateWithWriter([]string{"--rules", dir, "--provider", "alicloud", "--format", "table"}, &tableOut); err != nil {
		t.Fatalf("rules validate table returned error: %v", err)
	}
	for _, want := range []string{"Provider", "alicloud.oss.validate", "Totals"} {
		if !strings.Contains(tableOut.String(), want) {
			t.Fatalf("table output missing %q:\n%s", want, tableOut.String())
		}
	}
}

func TestParseServeConfigWithRulesAndProvider(t *testing.T) {
	dir := t.TempDir()

	config, err := parseServeConfig([]string{"--addr", "127.0.0.1:9999", "--db", "test.db", "--rules", dir, "--provider", "mock"})
	if err != nil {
		t.Fatalf("parseServeConfig returned error: %v", err)
	}
	if config.Addr != "127.0.0.1:9999" || config.DBPath != "test.db" || config.RulesDir != dir || config.Provider != "mock" {
		t.Fatalf("unexpected serve config: %+v", config)
	}
}

func TestParseServeConfigUsesDefaultDBPath(t *testing.T) {
	dir := t.TempDir()

	config, err := parseServeConfig([]string{"--rules", dir})
	if err != nil {
		t.Fatalf("parseServeConfig returned error: %v", err)
	}
	if config.DBPath != core.DefaultDBPath() {
		t.Fatalf("DBPath = %q, want %q", config.DBPath, core.DefaultDBPath())
	}
}

func TestParseServeConfigMissingRulesDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	_, err := parseServeConfig([]string{"--rules", missing})
	if err == nil {
		t.Fatal("expected missing rules directory error")
	}
	if !strings.Contains(err.Error(), "rules directory") || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected clear rules directory error, got %v", err)
	}
}

func writeCLIRulePack(t *testing.T, root string, name string, metadata string, input string) {
	t.Helper()

	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", dir, err)
	}
	files := map[string]string{
		"metadata.json": metadata,
		"policy.rego":   "package " + strings.ReplaceAll(name, "-", "_") + "\nimport rego.v1\ndefault risk := false\n",
		"input.json":    input,
	}
	for filename, content := range files {
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
}
