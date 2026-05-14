package rule

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadDirLoadsSamplePack(t *testing.T) {
	packs, err := LoadDir(sampleRulesDir(t))
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}

	pack := findSamplePack(t, packs)
	if pack.Metadata.ID != "mock.storage_bucket.public" {
		t.Fatalf("metadata id = %q", pack.Metadata.ID)
	}
	if pack.Policy == "" {
		t.Fatal("policy was not loaded")
	}
	if !strings.Contains(pack.Remediation, "Remove public access") {
		t.Fatalf("remediation was not loaded: %q", pack.Remediation)
	}
	if len(pack.Examples) != 2 {
		t.Fatalf("examples length = %d, want 2", len(pack.Examples))
	}
}

func TestLoadPackConvertsLegacyMetadata(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "metadata.json", `{
		"advice": "Enable private access only.",
		"categoryList": ["数据保护", "网络访问"],
		"code": "ALI_CLOUD_OSS_202501081111_313311",
		"context": "{$.messages}",
		"description": "阿里云-OSS-任意VPC访问",
		"level": "High",
		"link": "https://example.test/rule",
		"name": "阿里云-OSS-任意VPC访问",
		"platform": "ALI_CLOUD",
		"resourceType": "OSS"
	}`)
	writeRuleFile(t, dir, "policy.rego", `package legacy_oss
import rego.v1
default risk := false
`)
	writeRuleFile(t, dir, "input.json", `{"BucketPolicy": null}`)

	pack, err := LoadPack(dir)
	if err != nil {
		t.Fatalf("LoadPack() error = %v", err)
	}

	if pack.Metadata.ID != "ALI_CLOUD_OSS_202501081111_313311" {
		t.Fatalf("legacy id = %q", pack.Metadata.ID)
	}
	if pack.Metadata.Severity != SeverityHigh {
		t.Fatalf("legacy severity = %q", pack.Metadata.Severity)
	}
	if pack.Metadata.Provider != "ALI_CLOUD" {
		t.Fatalf("legacy provider = %q", pack.Metadata.Provider)
	}
	if pack.Metadata.Service != "OSS" || pack.Metadata.AssetType != "OSS" {
		t.Fatalf("legacy service/asset type = %q/%q", pack.Metadata.Service, pack.Metadata.AssetType)
	}
	if strings.Join(pack.Metadata.Categories, ",") != "数据保护,网络访问" {
		t.Fatalf("legacy categories = %#v", pack.Metadata.Categories)
	}
	if pack.Metadata.Context != "{$.messages}" || pack.Metadata.Advice == "" || pack.Metadata.Link == "" {
		t.Fatalf("legacy context/advice/link not converted: %#v", pack.Metadata)
	}
	if len(pack.Examples) != 1 || pack.Examples[0].Name != "input.json" || pack.Examples[0].WantFindings != -1 {
		t.Fatalf("input.json example = %#v", pack.Examples)
	}
}

func TestLoadPackReadsNestedLegacyAdvice(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "metadata.json", `{
		"id": "alicloud.account_202501081111_689362",
		"name": "阿里云-RAM-主账号启用AccessKey",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "account",
		"legacy": {
			"advice": "根据实际需要创建 RAM User 或 Role 进行 API 调用，删除主账号下的 AK。",
			"categoryList": ["身份安全"],
			"context": "{$.messages[0].Description}",
			"link": "https://example.test/ram"
		}
	}`)
	writeRuleFile(t, dir, "policy.rego", `package nested_legacy
import rego.v1
default risk := false
`)

	pack, err := LoadPack(dir)
	if err != nil {
		t.Fatalf("LoadPack() error = %v", err)
	}
	if !strings.Contains(pack.Metadata.Advice, "删除主账号下的 AK") {
		t.Fatalf("nested legacy advice was not loaded: %#v", pack.Metadata)
	}
	if pack.Metadata.Link != "https://example.test/ram" || pack.Metadata.Context == "" || strings.Join(pack.Metadata.Categories, ",") != "身份安全" {
		t.Fatalf("nested legacy metadata was not loaded: %#v", pack.Metadata)
	}
}

func TestLoadPackReadsNestedLegacyLinkedDataList(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "metadata.json", `{
		"id": "alicloud.ens_agent",
		"name": "ENS agent",
		"severity": "medium",
		"provider": "alicloud",
		"asset_type": "ens_instance",
		"legacy": {
			"linkedDataList": "[{\"associativeMode\":\"仅关联一次\",\"linkedKey1\":\"$.Instance.InstanceId\",\"linkedKey2\":\"$.Instance.InstanceId\",\"newKeyName\":\"InstanceInstalledAegis\",\"resourceType\":[\"SECURITY\",\"Sas\"]}]"
		}
	}`)
	writeRuleFile(t, dir, "policy.rego", `package ens_agent
import rego.v1
default risk := false
`)

	pack, err := LoadPack(dir)
	if err != nil {
		t.Fatalf("LoadPack() error = %v", err)
	}
	if len(pack.Metadata.LinkedData) != 1 {
		t.Fatalf("linked data specs = %#v", pack.Metadata.LinkedData)
	}
	spec := pack.Metadata.LinkedData[0]
	if spec.NewKeyName != "InstanceInstalledAegis" || spec.LinkedKey1 != "$.Instance.InstanceId" || spec.LinkedKey2 != "$.Instance.InstanceId" {
		t.Fatalf("unexpected linked data spec: %#v", spec)
	}
	if strings.Join(spec.ResourceType, ",") != "SECURITY,Sas" {
		t.Fatalf("resource type = %#v", spec.ResourceType)
	}
}

func sampleRulesDir(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "rules"))
}

func findSamplePack(t *testing.T, packs []RulePack) RulePack {
	t.Helper()

	for _, pack := range packs {
		if pack.Metadata.ID == "mock.storage_bucket.public" {
			return pack
		}
	}
	t.Fatalf("sample rule pack not found in %d pack(s)", len(packs))
	return RulePack{}
}

func writeRuleFile(t *testing.T, dir string, name string, content string) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
