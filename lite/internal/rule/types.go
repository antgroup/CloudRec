package rule

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type RulePack struct {
	Dir             string
	MetadataPath    string
	PolicyPath      string
	RemediationPath string
	ExamplesPath    string
	InputPath       string
	RelationPath    string
	DataPaths       []string
	MissingDataRefs []string

	Metadata    RuleMetadata
	Policy      string
	Remediation string
	Examples    []RuleExample
	Data        map[string]any
}

type RuleMetadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    Severity `json:"severity"`
	Provider    string   `json:"provider,omitempty"`
	Service     string   `json:"service,omitempty"`
	AssetType   string   `json:"asset_type,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Context     string   `json:"context,omitempty"`
	Advice      string   `json:"advice,omitempty"`
	Link        string   `json:"link,omitempty"`

	Query      string           `json:"query,omitempty"`
	EntryPoint string           `json:"entrypoint,omitempty"`
	Disabled   bool             `json:"disabled,omitempty"`
	LinkedData []LinkedDataSpec `json:"linked_data,omitempty"`
}

type LinkedDataSpec struct {
	AssociativeMode string   `json:"associativeMode,omitempty"`
	LinkedKey1      string   `json:"linkedKey1,omitempty"`
	LinkedKey2      string   `json:"linkedKey2,omitempty"`
	NewKeyName      string   `json:"newKeyName,omitempty"`
	ResourceType    []string `json:"resourceType,omitempty"`
}

func (m RuleMetadata) Validate() error {
	var missing []string
	if strings.TrimSpace(m.ID) == "" {
		missing = append(missing, "id")
	}
	if strings.TrimSpace(m.Name) == "" {
		missing = append(missing, "name")
	}
	if strings.TrimSpace(string(m.Severity)) == "" {
		missing = append(missing, "severity")
	}
	if len(missing) > 0 {
		return fmt.Errorf("metadata missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

type RuleExample struct {
	Name         string          `json:"name"`
	Input        json.RawMessage `json:"input"`
	WantFindings int             `json:"want_findings"`
}

func (e RuleExample) InputValue() (any, error) {
	if len(e.Input) == 0 {
		return nil, errors.New("example input is empty")
	}

	var value any
	if err := json.Unmarshal(e.Input, &value); err != nil {
		return nil, fmt.Errorf("decode example input %q: %w", e.Name, err)
	}
	return value, nil
}

type FindingResult struct {
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Risk        string         `json:"risk,omitempty"`
	Severity    Severity       `json:"severity"`
	Provider    string         `json:"provider,omitempty"`
	Service     string         `json:"service,omitempty"`
	AssetType   string         `json:"asset_type,omitempty"`
	AssetID     string         `json:"asset_id,omitempty"`
	AccountID   string         `json:"account_id,omitempty"`
	Region      string         `json:"region,omitempty"`
	Title       string         `json:"title,omitempty"`
	Message     string         `json:"message,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}
