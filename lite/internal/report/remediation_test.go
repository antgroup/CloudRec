package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/model"
)

func TestRenderRemediationExportMarkdownRedactsSensitiveEvidence(t *testing.T) {
	findings := []model.FindingView{{
		Finding: model.Finding{
			AccountID:   "account-1",
			RuleID:      "rule-1",
			Title:       "Risky bucket",
			Severity:    model.SeverityHigh,
			Status:      model.FindingStatusOpen,
			Message:     "Bucket is public.",
			Evidence:    json.RawMessage(`{"AccessKeyId":"LTAI-unit-ak","nested":{"token":"unit-token"},"safe":true}`),
			Remediation: "Disable public access.",
		},
		Provider:          "alicloud",
		Region:            "cn-hangzhou",
		AssetResourceType: "OSS",
		AssetResourceID:   "bucket-1",
	}}

	var out bytes.Buffer
	err := RenderRemediationExport(&out, findings, RemediationExportOptions{
		Format:      FormatMarkdown,
		GeneratedAt: time.Date(2026, 5, 3, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("render remediation export: %v", err)
	}
	body := out.String()
	for _, want := range []string{"CloudRec Lite Remediation Notes", "Risky bucket", "Disable public access.", "[redacted]", "cloudrec-lite scan --provider alicloud"} {
		if !strings.Contains(body, want) {
			t.Fatalf("markdown output missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "LTAI-unit-ak") || strings.Contains(body, "unit-token") {
		t.Fatalf("markdown output leaked sensitive evidence:\n%s", body)
	}
}

func TestRenderRemediationExportHTML(t *testing.T) {
	var out bytes.Buffer
	err := RenderRemediationExport(&out, []model.FindingView{{
		Finding: model.Finding{
			RuleID:      "rule-1",
			Title:       "Risky resource",
			Severity:    model.SeverityMedium,
			Status:      model.FindingStatusOpen,
			Remediation: "Fix it.",
		},
	}}, RemediationExportOptions{Format: FormatHTML})
	if err != nil {
		t.Fatalf("render html remediation export: %v", err)
	}
	if !strings.Contains(out.String(), "<html") || !strings.Contains(out.String(), "Risky resource") {
		t.Fatalf("unexpected html output:\n%s", out.String())
	}
}
