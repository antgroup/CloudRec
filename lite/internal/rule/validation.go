package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
)

const (
	ValidationFormatJSON  = "json"
	ValidationFormatTable = "table"

	ValidationStatusFixtureOnly      = "fixture_only"
	ValidationStatusRealField        = "real_field_verified"
	ValidationStatusNeedsFixture     = "needs_fixture"
	ValidationStatusNeedsLogicChange = "needs_logic_change"
)

type ValidationOptions struct {
	RulesDir   string
	Provider   string
	SamplesDir string
}

type ValidationReport struct {
	Provider string           `json:"provider"`
	Totals   ValidationTotals `json:"totals"`
	Rules    []RuleValidation `json:"rules"`
}

type ValidationTotals struct {
	TotalRules        int `json:"total_rules"`
	FixtureOnly       int `json:"fixture_only"`
	RealFieldVerified int `json:"real_field_verified"`
	NeedsFixture      int `json:"needs_fixture"`
	NeedsLogicChange  int `json:"needs_logic_change"`
	Examples          int `json:"examples"`
	PassedExamples    int `json:"passed_examples"`
	FailedExamples    int `json:"failed_examples"`
	FieldSamples      int `json:"field_samples"`
	MissingInputRefs  int `json:"missing_input_refs"`
	MissingSampleRefs int `json:"missing_sample_refs"`
}

type RuleValidation struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Provider           string   `json:"provider"`
	ResourceType       string   `json:"resource_type"`
	Severity           string   `json:"severity"`
	ValidationStatus   string   `json:"validation_status"`
	Examples           int      `json:"examples"`
	PassedExamples     int      `json:"passed_examples"`
	FailedExamples     int      `json:"failed_examples"`
	ExpectedUnknown    int      `json:"expected_unknown"`
	FieldSamples       int      `json:"field_samples"`
	InputReferences    []string `json:"input_references,omitempty"`
	MissingFixtureRefs []string `json:"missing_fixture_refs,omitempty"`
	MissingSampleRefs  []string `json:"missing_sample_refs,omitempty"`
	Errors             []string `json:"errors,omitempty"`
	RuleDir            string   `json:"rule_dir,omitempty"`
}

func AnalyzeValidation(ctx context.Context, options ValidationOptions) (ValidationReport, error) {
	packs, err := LoadDirWithOptions(options.RulesDir, LoadDirOptions{IncludeDisabled: true})
	if err != nil {
		return ValidationReport{}, err
	}
	provider := cleanProvider(options.Provider)
	evaluator := NewEvaluator(NewOPAEngine())
	samples, err := loadFieldSamples(options.SamplesDir)
	if err != nil {
		return ValidationReport{}, err
	}

	rows := make([]RuleValidation, 0, len(packs))
	for _, pack := range packs {
		ruleProvider := cleanProvider(pack.Metadata.Provider)
		if ruleProvider == "" {
			ruleProvider = provider
		}
		if provider != "" && ruleProvider != provider {
			continue
		}
		row := RuleValidation{
			ID:               pack.Metadata.ID,
			Name:             pack.Metadata.Name,
			Provider:         firstNonEmpty(ruleProvider, "unknown"),
			ResourceType:     cleanResourceType(firstNonEmpty(pack.Metadata.AssetType, pack.Metadata.Service, "unknown")),
			Severity:         string(pack.Metadata.Severity),
			InputReferences:  extractInputReferences(pack.Policy),
			ValidationStatus: ValidationStatusNeedsFixture,
			RuleDir:          pack.Dir,
		}
		if len(pack.Examples) == 0 {
			rows = append(rows, row)
			continue
		}
		row.Examples = len(pack.Examples)
		missingRefs := map[string]bool{}
		for _, example := range pack.Examples {
			input, err := example.InputValue()
			if err != nil {
				row.FailedExamples++
				row.Errors = append(row.Errors, fmt.Sprintf("%s: %v", example.Name, err))
				continue
			}
			for _, ref := range row.InputReferences {
				if !inputRefExists(input, ref) {
					missingRefs[ref] = true
				}
			}
			findings, err := evaluator.Evaluate(ctx, []RulePack{pack}, input)
			if err != nil {
				row.FailedExamples++
				row.Errors = append(row.Errors, fmt.Sprintf("%s: %v", example.Name, err))
				continue
			}
			if example.WantFindings >= 0 && len(findings) != example.WantFindings {
				row.FailedExamples++
				row.Errors = append(row.Errors, fmt.Sprintf("%s: findings=%d want=%d", example.Name, len(findings), example.WantFindings))
				continue
			}
			if example.WantFindings < 0 {
				row.ExpectedUnknown++
			}
			row.PassedExamples++
		}
		row.MissingFixtureRefs = sortedBoolKeys(missingRefs)
		if row.FailedExamples > 0 {
			row.ValidationStatus = ValidationStatusNeedsLogicChange
		} else {
			row.ValidationStatus = ValidationStatusFixtureOnly
		}
		row.FieldSamples, row.MissingSampleRefs = verifyInputRefsWithSamples(row.ResourceType, row.InputReferences, samples)
		if row.ValidationStatus == ValidationStatusFixtureOnly && row.FieldSamples > 0 && len(row.MissingSampleRefs) == 0 {
			row.ValidationStatus = ValidationStatusRealField
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ResourceType != rows[j].ResourceType {
			return rows[i].ResourceType < rows[j].ResourceType
		}
		return rows[i].ID < rows[j].ID
	})

	report := ValidationReport{
		Provider: provider,
		Rules:    rows,
	}
	report.Totals.TotalRules = len(rows)
	for _, row := range rows {
		report.Totals.Examples += row.Examples
		report.Totals.PassedExamples += row.PassedExamples
		report.Totals.FailedExamples += row.FailedExamples
		report.Totals.FieldSamples += row.FieldSamples
		report.Totals.MissingInputRefs += len(row.MissingFixtureRefs)
		report.Totals.MissingSampleRefs += len(row.MissingSampleRefs)
		switch row.ValidationStatus {
		case ValidationStatusFixtureOnly:
			report.Totals.FixtureOnly++
		case ValidationStatusRealField:
			report.Totals.RealFieldVerified++
		case ValidationStatusNeedsFixture:
			report.Totals.NeedsFixture++
		case ValidationStatusNeedsLogicChange:
			report.Totals.NeedsLogicChange++
		}
	}
	return report, nil
}

func RenderValidation(w io.Writer, report ValidationReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", ValidationFormatTable:
		return renderValidationTable(w, report)
	case ValidationFormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	default:
		return fmt.Errorf("unknown validation format %q", format)
	}
}

func renderValidationTable(w io.Writer, report ValidationReport) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "Provider\tResource Type\tRule ID\tStatus\tExamples\tPassed\tFailed\tField Samples\tMissing Refs\tMissing Sample Refs"); err != nil {
		return err
	}
	for _, item := range report.Rules {
		if _, err := fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			item.Provider,
			item.ResourceType,
			item.ID,
			item.ValidationStatus,
			item.Examples,
			item.PassedExamples,
			item.FailedExamples,
			item.FieldSamples,
			len(item.MissingFixtureRefs),
			len(item.MissingSampleRefs),
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(
		tw,
		"\nTotals\t%d rules\t%d fixture only\t%d real field verified\t%d needs fixture\t%d needs logic change\t%d examples\t%d passed\t%d failed\t%d field samples\t%d missing refs\t%d missing sample refs\n",
		report.Totals.TotalRules,
		report.Totals.FixtureOnly,
		report.Totals.RealFieldVerified,
		report.Totals.NeedsFixture,
		report.Totals.NeedsLogicChange,
		report.Totals.Examples,
		report.Totals.PassedExamples,
		report.Totals.FailedExamples,
		report.Totals.FieldSamples,
		report.Totals.MissingInputRefs,
		report.Totals.MissingSampleRefs,
	); err != nil {
		return err
	}
	return tw.Flush()
}

func inputRefExists(input any, ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return true
	}
	return inputPathExists(input, strings.Split(ref, "."))
}

func inputPathExists(value any, parts []string) bool {
	if len(parts) == 0 {
		return true
	}
	value = normalizeInputValue(value)
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if inputPathExists(item, parts) {
				return true
			}
		}
		return false
	}
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	next, ok := object[parts[0]]
	if !ok {
		return false
	}
	return inputPathExists(next, parts[1:])
}

func normalizeInputValue(value any) any {
	if raw, ok := value.(json.RawMessage); ok {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err == nil {
			return decoded
		}
	}
	return value
}

func sortedBoolKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type fieldSample struct {
	ResourceType string
	Input        any
}

func loadFieldSamples(root string) ([]fieldSample, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat samples directory %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("samples path %q is not a directory", root)
	}
	samples := make([]fieldSample, 0)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read field sample %q: %w", path, err)
		}
		var raw any
		if err := json.Unmarshal(content, &raw); err != nil {
			return fmt.Errorf("decode field sample %q: %w", path, err)
		}
		sample := fieldSampleFromValue(raw, path)
		if sample.Input == nil {
			return nil
		}
		samples = append(samples, sample)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk samples directory %q: %w", root, err)
	}
	return samples, nil
}

func fieldSampleFromValue(value any, path string) fieldSample {
	object, _ := normalizeInputValue(value).(map[string]any)
	resourceType := ""
	input := value
	if len(object) > 0 {
		resourceType = firstStringValue(
			object["resource_type"],
			object["resourceType"],
			object["asset_type"],
			object["assetType"],
			object["type"],
		)
		if wrapped, ok := object["input"]; ok {
			input = wrapped
		}
	}
	if resourceType == "" {
		resourceType = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return fieldSample{
		ResourceType: cleanResourceType(resourceType),
		Input:        normalizeInputValue(input),
	}
}

func verifyInputRefsWithSamples(resourceType string, refs []string, samples []fieldSample) (int, []string) {
	if len(samples) == 0 {
		return 0, nil
	}
	matched := make([]fieldSample, 0)
	for _, sample := range samples {
		if sameCleanResourceType(sample.ResourceType, resourceType) {
			matched = append(matched, sample)
		}
	}
	if len(matched) == 0 {
		return 0, nil
	}
	missing := map[string]bool{}
	for _, ref := range refs {
		found := false
		for _, sample := range matched {
			if inputRefExists(sample.Input, ref) {
				found = true
				break
			}
		}
		if !found {
			missing[ref] = true
		}
	}
	return len(matched), sortedBoolKeys(missing)
}

func firstStringValue(values ...any) string {
	for _, value := range values {
		if text := strings.TrimSpace(fmt.Sprint(value)); text != "" && text != "<nil>" {
			return text
		}
	}
	return ""
}

func sameCleanResourceType(left string, right string) bool {
	return compactResourceType(cleanResourceType(left)) == compactResourceType(cleanResourceType(right))
}

func compactResourceType(resourceType string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(resourceType)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
