package rule

import (
	"fmt"
	"strings"
)

func findingsFromValue(pack RulePack, value any) ([]FindingResult, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case bool:
		if !typed {
			return nil, nil
		}
		return []FindingResult{baseFinding(pack)}, nil
	case string:
		finding := baseFinding(pack)
		finding.Message = typed
		return []FindingResult{finding}, nil
	case []any:
		findings := make([]FindingResult, 0, len(typed))
		for _, item := range typed {
			itemFindings, err := findingsFromValue(pack, item)
			if err != nil {
				return nil, err
			}
			findings = append(findings, itemFindings...)
		}
		return findings, nil
	case map[string]any:
		if nested, ok := typed["findings"]; ok {
			return findingsFromValue(pack, nested)
		}
		return []FindingResult{findingFromMap(pack, typed)}, nil
	default:
		return nil, fmt.Errorf("unsupported finding result type %T", value)
	}
}

func baseFinding(pack RulePack) FindingResult {
	message := pack.Metadata.Description
	if strings.TrimSpace(message) == "" {
		message = pack.Metadata.Name
	}

	remediation := strings.TrimSpace(pack.Remediation)
	if remediation == "" {
		remediation = strings.TrimSpace(pack.Metadata.Advice)
	}

	metadata := map[string]any{}
	if pack.Metadata.Context != "" {
		metadata["context"] = pack.Metadata.Context
	}
	if pack.Metadata.Link != "" {
		metadata["link"] = pack.Metadata.Link
	}
	if len(pack.Metadata.Categories) > 0 {
		metadata["categories"] = pack.Metadata.Categories
	}
	if len(metadata) == 0 {
		metadata = nil
	}

	return FindingResult{
		RuleID:      pack.Metadata.ID,
		RuleName:    pack.Metadata.Name,
		Risk:        pack.Metadata.ID,
		Severity:    pack.Metadata.Severity,
		Provider:    pack.Metadata.Provider,
		Service:     pack.Metadata.Service,
		AssetType:   pack.Metadata.AssetType,
		Title:       pack.Metadata.Name,
		Message:     message,
		Remediation: remediation,
		Metadata:    metadata,
	}
}

func findingFromMap(pack RulePack, raw map[string]any) FindingResult {
	finding := baseFinding(pack)
	known := map[string]struct{}{}

	applyString := func(field string, apply func(string)) {
		if value, ok := stringValue(raw[field]); ok {
			known[field] = struct{}{}
			apply(value)
		}
	}

	applyString("rule_id", func(value string) { finding.RuleID = value })
	applyString("rule_name", func(value string) { finding.RuleName = value })
	applyString("risk", func(value string) { finding.Risk = value })
	applyString("risk_type", func(value string) { finding.Risk = value })
	applyString("severity", func(value string) { finding.Severity = Severity(value) })
	applyString("provider", func(value string) { finding.Provider = value })
	applyString("service", func(value string) { finding.Service = value })
	applyString("asset_type", func(value string) { finding.AssetType = value })
	applyString("asset_id", func(value string) { finding.AssetID = value })
	applyString("resource_id", func(value string) { finding.AssetID = value })
	applyString("account_id", func(value string) { finding.AccountID = value })
	applyString("account", func(value string) { finding.AccountID = value })
	applyString("region", func(value string) { finding.Region = value })
	applyString("title", func(value string) { finding.Title = value })
	applyString("message", func(value string) { finding.Message = value })
	applyString("description", func(value string) { finding.Message = value })

	if evidence, ok := raw["evidence"]; ok {
		known["evidence"] = struct{}{}
		if evidenceMap, ok := evidence.(map[string]any); ok {
			finding.Evidence = evidenceMap
		} else {
			finding.Evidence = map[string]any{"value": evidence}
		}
	}

	if metadata, ok := raw["metadata"].(map[string]any); ok {
		known["metadata"] = struct{}{}
		finding.Metadata = metadata
	}

	for key, value := range raw {
		if _, ok := known[key]; ok {
			continue
		}
		if finding.Metadata == nil {
			finding.Metadata = map[string]any{}
		}
		finding.Metadata[key] = value
	}

	if finding.Title == "" {
		finding.Title = finding.RuleName
	}
	if finding.Message == "" {
		finding.Message = finding.Title
	}
	return finding
}

func stringValue(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case fmt.Stringer:
		return typed.String(), true
	default:
		return "", false
	}
}
