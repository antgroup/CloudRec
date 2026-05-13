package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/model"
)

const (
	FormatMarkdown = "markdown"
	FormatHTML     = "html"
)

type RemediationExportOptions struct {
	Format      string
	GeneratedAt time.Time
}

type remediationNote struct {
	Index       int
	Title       string
	RuleID      string
	Severity    string
	Status      string
	AccountID   string
	Provider    string
	Resource    string
	ResourceID  string
	Region      string
	Message     string
	Evidence    string
	Remediation string
	Verify      string
}

func RenderRemediationExport(w io.Writer, findings []model.FindingView, options RemediationExportOptions) error {
	if w == nil {
		return fmt.Errorf("remediation export writer is required")
	}
	generatedAt := options.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	notes := buildRemediationNotes(findings)
	switch strings.ToLower(strings.TrimSpace(options.Format)) {
	case "", FormatMarkdown:
		return renderRemediationMarkdown(w, notes, generatedAt)
	case FormatHTML:
		return renderRemediationHTML(w, notes, generatedAt)
	case FormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{
			"generated_at": generatedAt.Format(time.RFC3339),
			"count":        len(notes),
			"findings":     notes,
		})
	default:
		return fmt.Errorf("unsupported remediation export format %q", options.Format)
	}
}

func buildRemediationNotes(findings []model.FindingView) []remediationNote {
	notes := make([]remediationNote, 0, len(findings))
	for i, finding := range findings {
		resourceType := firstNonEmptyString(finding.AssetResourceType, finding.Asset.ResourceType)
		resourceID := firstNonEmptyString(finding.AssetResourceID, finding.Asset.ResourceID)
		provider := firstNonEmptyString(finding.Provider, finding.Asset.Provider)
		region := firstNonEmptyString(finding.Region, finding.Asset.Region)
		note := remediationNote{
			Index:       i + 1,
			Title:       firstNonEmptyString(finding.Title, finding.RuleID),
			RuleID:      finding.RuleID,
			Severity:    finding.Severity,
			Status:      finding.Status,
			AccountID:   finding.AccountID,
			Provider:    provider,
			Resource:    resourceType,
			ResourceID:  resourceID,
			Region:      region,
			Message:     finding.Message,
			Evidence:    redactedEvidence(finding.Evidence),
			Remediation: strings.TrimSpace(finding.Remediation),
			Verify:      verificationCommand(provider, finding.AccountID, resourceType),
		}
		notes = append(notes, note)
	}
	return notes
}

func renderRemediationMarkdown(w io.Writer, notes []remediationNote, generatedAt time.Time) error {
	if _, err := fmt.Fprintf(w, "# CloudRec Lite Remediation Notes\n\nGenerated: %s\n\nTotal findings: %d\n", generatedAt.Format(time.RFC3339), len(notes)); err != nil {
		return err
	}
	for _, note := range notes {
		if _, err := fmt.Fprintf(w, "\n## %d. %s\n\n", note.Index, note.Title); err != nil {
			return err
		}
		rows := []string{
			"Rule: " + note.RuleID,
			"Severity: " + note.Severity,
			"Status: " + note.Status,
			"Account: " + note.AccountID,
			"Provider: " + note.Provider,
			"Resource: " + note.Resource,
			"Resource ID: " + note.ResourceID,
			"Region: " + note.Region,
		}
		for _, row := range rows {
			if strings.TrimSpace(strings.TrimPrefix(row, strings.Split(row, ":")[0]+":")) == "" {
				continue
			}
			if _, err := fmt.Fprintf(w, "- %s\n", row); err != nil {
				return err
			}
		}
		if strings.TrimSpace(note.Message) != "" {
			if _, err := fmt.Fprintf(w, "\n### Why This Matters\n\n%s\n", note.Message); err != nil {
				return err
			}
		}
		if strings.TrimSpace(note.Evidence) != "" {
			if _, err := fmt.Fprintf(w, "\n### Evidence\n\n```json\n%s\n```\n", note.Evidence); err != nil {
				return err
			}
		}
		if strings.TrimSpace(note.Remediation) != "" {
			if _, err := fmt.Fprintf(w, "\n### Remediation\n\n%s\n", note.Remediation); err != nil {
				return err
			}
		}
		if strings.TrimSpace(note.Verify) != "" {
			if _, err := fmt.Fprintf(w, "\n### Verification\n\n```sh\n%s\n```\n", note.Verify); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderRemediationHTML(w io.Writer, notes []remediationNote, generatedAt time.Time) error {
	tmpl := template.Must(template.New("remediation").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CloudRec Lite Remediation Notes</title>
  <style>
    body { margin: 0; padding: 40px; background: #eef7ff; color: #102033; font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width: 1040px; margin: 0 auto; }
    .finding { margin: 24px 0; padding: 24px; border: 1px solid #cfe1f3; border-radius: 24px; background: rgba(255,255,255,.88); box-shadow: 0 18px 55px rgba(45, 118, 184, .12); }
    .meta { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
    .chip { padding: 6px 10px; border-radius: 999px; background: #e8f3ff; color: #28577d; font-size: 12px; font-weight: 700; }
    pre { overflow: auto; padding: 16px; border-radius: 16px; background: #0f2033; color: #e9f6ff; }
    h1, h2 { letter-spacing: -.03em; }
  </style>
</head>
<body>
<main>
  <h1>CloudRec Lite Remediation Notes</h1>
  <p>Generated: {{.GeneratedAt}} · Total findings: {{len .Notes}}</p>
  {{range .Notes}}
  <section class="finding">
    <h2>{{.Index}}. {{.Title}}</h2>
    <div class="meta">
      <span class="chip">rule {{.RuleID}}</span>
      <span class="chip">severity {{.Severity}}</span>
      <span class="chip">status {{.Status}}</span>
      <span class="chip">resource {{.Resource}}</span>
      <span class="chip">region {{.Region}}</span>
    </div>
    {{if .Message}}<h3>Why This Matters</h3><p>{{.Message}}</p>{{end}}
    {{if .Evidence}}<h3>Evidence</h3><pre>{{.Evidence}}</pre>{{end}}
    {{if .Remediation}}<h3>Remediation</h3><p>{{.Remediation}}</p>{{end}}
    {{if .Verify}}<h3>Verification</h3><pre>{{.Verify}}</pre>{{end}}
  </section>
  {{end}}
</main>
</body>
</html>`))
	return tmpl.Execute(w, map[string]any{
		"GeneratedAt": generatedAt.Format(time.RFC3339),
		"Notes":       notes,
	})
}

func redactedEvidence(raw json.RawMessage) string {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" || string(raw) == "null" {
		return ""
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return redactSensitiveText(string(raw))
	}
	redacted := redactJSONValue(value)
	encoded, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return ""
	}
	return string(encoded)
}

func redactJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		output := map[string]any{}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if sensitiveEvidenceKey(key) {
				output[key] = "[redacted]"
				continue
			}
			output[key] = redactJSONValue(typed[key])
		}
		return output
	case []any:
		output := make([]any, 0, len(typed))
		for _, item := range typed {
			output = append(output, redactJSONValue(item))
		}
		return output
	case string:
		return redactSensitiveText(typed)
	default:
		return value
	}
}

func sensitiveEvidenceKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	sensitiveTokens := []string{"access_key", "accesskey", "secret", "token", "password", "passwd", "credential", "ak", "sk"}
	for _, token := range sensitiveTokens {
		if normalized == token || strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func redactSensitiveText(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "LTAI") && len(trimmed) >= 16 {
		return "[redacted]"
	}
	return value
}

func verificationCommand(provider string, accountID string, resourceType string) string {
	provider = strings.TrimSpace(provider)
	accountID = strings.TrimSpace(accountID)
	resourceType = strings.TrimSpace(resourceType)
	if provider == "" || accountID == "" {
		return ""
	}
	command := fmt.Sprintf("cloudrec-lite scan --provider %s --account %s --dry-run=true", shellQuote(provider), shellQuote(accountID))
	if resourceType != "" {
		command += " --resource-types " + shellQuote(resourceType)
	}
	return command
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("-_./:", r)
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
