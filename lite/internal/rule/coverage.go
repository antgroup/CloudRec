package rule

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

const (
	CoverageFormatJSON  = "json"
	CoverageFormatTable = "table"
)

type CoverageOptions struct {
	RulesDir         string
	Provider         string
	Catalog          []CoverageCatalogSpec
	NativeAdapters   map[string]bool
	SamplesDir       string
	ReviewLedgerPath string
}

type CoverageCatalogSpec struct {
	Type       string `json:"type"`
	Normalized string `json:"normalized,omitempty"`
	Group      string `json:"group,omitempty"`
	Dimension  string `json:"dimension,omitempty"`
}

type CoverageReport struct {
	Provider  string             `json:"provider"`
	Totals    CoverageTotals     `json:"totals"`
	Resources []ResourceCoverage `json:"resources"`
}

type CoverageTotals struct {
	ResourceTypes       int `json:"resource_types"`
	TotalRules          int `json:"total_rules"`
	WithExamples        int `json:"with_examples"`
	MissingDataRefs     int `json:"missing_data_refs"`
	Disabled            int `json:"disabled"`
	OfficialReviewed    int `json:"official_reviewed,omitempty"`
	NeedsReview         int `json:"needs_review,omitempty"`
	NeedsOfficialDocs   int `json:"needs_official_docs,omitempty"`
	Blocked             int `json:"blocked,omitempty"`
	NeedsLogicChange    int `json:"needs_logic_change,omitempty"`
	WithRemediation     int `json:"with_remediation,omitempty"`
	MissingRemediation  int `json:"missing_remediation,omitempty"`
	VerifiedResources   int `json:"verified_resources,omitempty"`
	MissingSampleRefs   int `json:"missing_sample_refs,omitempty"`
	MissingSampleGroups int `json:"missing_sample_groups,omitempty"`
}

type ResourceCoverage struct {
	Provider             string   `json:"provider"`
	ResourceType         string   `json:"resource_type"`
	Normalized           string   `json:"normalized"`
	TotalRules           int      `json:"total_rules"`
	WithExamples         int      `json:"with_examples"`
	MissingDataRefs      int      `json:"missing_data_refs"`
	Disabled             int      `json:"disabled"`
	OfficialReviewed     int      `json:"official_reviewed,omitempty"`
	NeedsReview          int      `json:"needs_review,omitempty"`
	NeedsOfficialDocs    int      `json:"needs_official_docs,omitempty"`
	Blocked              int      `json:"blocked,omitempty"`
	NeedsLogicChange     int      `json:"needs_logic_change,omitempty"`
	WithRemediation      int      `json:"with_remediation,omitempty"`
	MissingRemediation   int      `json:"missing_remediation,omitempty"`
	FieldSamples         int      `json:"field_samples,omitempty"`
	MissingSampleRefs    int      `json:"missing_sample_refs,omitempty"`
	MissingSampleFields  []string `json:"missing_sample_fields,omitempty"`
	CollectorFieldStatus string   `json:"collector_field_status,omitempty"`
	ProviderSupported    bool     `json:"provider_supported"`
	NativeAdapter        bool     `json:"native_adapter"`
	CatalogType          string   `json:"catalog_type,omitempty"`
	Group                string   `json:"group,omitempty"`
	Dimension            string   `json:"dimension,omitempty"`
}

func AnalyzeCoverage(options CoverageOptions) (CoverageReport, error) {
	packs, err := LoadDirWithOptions(options.RulesDir, LoadDirOptions{IncludeDisabled: true})
	if err != nil {
		return CoverageReport{}, err
	}

	provider := cleanProvider(options.Provider)
	catalog := indexCoverageCatalog(options.Catalog)
	nativeAdapters := normalizeBoolSet(options.NativeAdapters)
	docs := normalizeOfficialDocs(DefaultOfficialDocs(provider))
	ledger, err := loadReviewLedger(options.ReviewLedgerPath)
	if err != nil {
		return CoverageReport{}, err
	}
	samples, err := loadFieldSamples(options.SamplesDir)
	if err != nil {
		return CoverageReport{}, err
	}
	resources := map[string]*ResourceCoverage{}
	resourceRefs := map[string]map[string]bool{}

	for _, pack := range packs {
		ruleProvider := cleanProvider(pack.Metadata.Provider)
		if ruleProvider == "" {
			ruleProvider = provider
		}
		if provider != "" && ruleProvider != provider {
			continue
		}

		resourceType := cleanResourceType(firstNonEmpty(pack.Metadata.AssetType, pack.Metadata.Service, "unknown"))
		normalized := normalizeResourceKey(resourceType)
		key := ruleProvider + "\x00" + normalized

		row, ok := resources[key]
		if !ok {
			row = &ResourceCoverage{
				Provider:     firstNonEmpty(ruleProvider, "unknown"),
				ResourceType: resourceType,
				Normalized:   normalized,
			}
			if spec, ok := catalog[normalized]; ok {
				row.ProviderSupported = true
				row.CatalogType = spec.Type
				row.ResourceType = firstNonEmpty(spec.Type, row.ResourceType)
				row.Group = spec.Group
				row.Dimension = spec.Dimension
			}
			row.NativeAdapter = nativeAdapters[normalized]
			resources[key] = row
		}

		row.TotalRules++
		if len(pack.Examples) > 0 || pack.InputPath != "" {
			row.WithExamples++
		}
		row.MissingDataRefs += len(pack.MissingDataRefs)
		if pack.Metadata.Disabled {
			row.Disabled++
		}
		if ruleHasRemediation(pack) {
			row.WithRemediation++
		} else {
			row.MissingRemediation++
		}
		status := coverageReviewStatus(pack, provider, docs, ledger)
		switch status {
		case AuditStatusOfficialReviewed:
			row.OfficialReviewed++
		case AuditStatusNeedsOfficialDocs:
			row.NeedsOfficialDocs++
		case AuditStatusBlocked:
			row.Blocked++
		case AuditStatusNeedsLogicChange:
			row.NeedsLogicChange++
		default:
			row.NeedsReview++
		}
		refs := resourceRefs[key]
		if refs == nil {
			refs = map[string]bool{}
			resourceRefs[key] = refs
		}
		for _, ref := range extractInputReferences(pack.Policy) {
			refs[ref] = true
		}
	}

	rows := make([]ResourceCoverage, 0, len(resources))
	for key, row := range resources {
		refs := sortedBoolKeys(resourceRefs[key])
		row.FieldSamples, row.MissingSampleFields = verifyInputRefsWithSamples(row.ResourceType, refs, samples)
		row.MissingSampleRefs = len(row.MissingSampleFields)
		row.CollectorFieldStatus = collectorFieldStatus(refs, row.FieldSamples, row.MissingSampleFields)
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Provider != rows[j].Provider {
			return rows[i].Provider < rows[j].Provider
		}
		return rows[i].Normalized < rows[j].Normalized
	})

	report := CoverageReport{
		Provider:  provider,
		Resources: rows,
	}
	report.Totals.ResourceTypes = len(rows)
	for _, row := range rows {
		report.Totals.TotalRules += row.TotalRules
		report.Totals.WithExamples += row.WithExamples
		report.Totals.MissingDataRefs += row.MissingDataRefs
		report.Totals.Disabled += row.Disabled
		report.Totals.OfficialReviewed += row.OfficialReviewed
		report.Totals.NeedsReview += row.NeedsReview
		report.Totals.NeedsOfficialDocs += row.NeedsOfficialDocs
		report.Totals.Blocked += row.Blocked
		report.Totals.NeedsLogicChange += row.NeedsLogicChange
		report.Totals.WithRemediation += row.WithRemediation
		report.Totals.MissingRemediation += row.MissingRemediation
		if row.CollectorFieldStatus == "verified" || row.CollectorFieldStatus == "no_input_refs" {
			report.Totals.VerifiedResources++
		}
		report.Totals.MissingSampleRefs += row.MissingSampleRefs
		if row.CollectorFieldStatus == "missing_samples" || row.CollectorFieldStatus == "missing_fields" {
			report.Totals.MissingSampleGroups++
		}
	}
	return report, nil
}

func RenderCoverage(w io.Writer, report CoverageReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", CoverageFormatTable:
		return renderCoverageTable(w, report)
	case CoverageFormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	default:
		return fmt.Errorf("unknown coverage format %q", format)
	}
}

func renderCoverageTable(w io.Writer, report CoverageReport) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintf(tw, "Provider\tResource Type\tRules\tExamples\tMissing Refs\tDisabled\tReview\tBlocked\tLogic Change\tFields\tRemediation\tSupported\tNative\tGroup\tDimension\n"); err != nil {
		return err
	}
	for _, row := range report.Resources {
		if _, err := fmt.Fprintf(
			tw,
			"%s\t%s\t%d\t%d\t%d\t%d\t%d/%d\t%d\t%d\t%s\t%d/%d\t%t\t%t\t%s\t%s\n",
			row.Provider,
			row.ResourceType,
			row.TotalRules,
			row.WithExamples,
			row.MissingDataRefs,
			row.Disabled,
			row.OfficialReviewed,
			row.TotalRules,
			row.Blocked,
			row.NeedsLogicChange,
			firstNonEmpty(row.CollectorFieldStatus, "unknown"),
			row.WithRemediation,
			row.TotalRules,
			row.ProviderSupported,
			row.NativeAdapter,
			row.Group,
			row.Dimension,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(
		tw,
		"\nTotals\t%d resource types\t%d\t%d\t%d\t%d\t%d official reviewed\t%d needs review\t%d missing docs\t%d blocked\t%d needs logic change\t%d with remediation\t%d missing remediation\t%d verified resources\t%d missing sample refs\t%d missing sample groups\t\t\t\t\t\n",
		report.Totals.ResourceTypes,
		report.Totals.TotalRules,
		report.Totals.WithExamples,
		report.Totals.MissingDataRefs,
		report.Totals.Disabled,
		report.Totals.OfficialReviewed,
		report.Totals.NeedsReview,
		report.Totals.NeedsOfficialDocs,
		report.Totals.Blocked,
		report.Totals.NeedsLogicChange,
		report.Totals.WithRemediation,
		report.Totals.MissingRemediation,
		report.Totals.VerifiedResources,
		report.Totals.MissingSampleRefs,
		report.Totals.MissingSampleGroups,
	); err != nil {
		return err
	}
	return tw.Flush()
}

func coverageReviewStatus(pack RulePack, provider string, docs map[string][]OfficialDoc, ledger map[string]RuleReviewRecord) string {
	if record, ok := ledger[pack.Metadata.ID]; ok {
		if status := normalizeAuditStatus(record.ReviewStatus); status != "" {
			return status
		}
		if strings.TrimSpace(record.BlockingReason) != "" {
			return AuditStatusBlocked
		}
	}
	resourceType := cleanResourceType(firstNonEmpty(pack.Metadata.AssetType, pack.Metadata.Service, "unknown"))
	if len(docs[normalizeResourceKey(resourceType)]) == 0 {
		return AuditStatusNeedsOfficialDocs
	}
	return AuditStatusNeedsReview
}

func collectorFieldStatus(refs []string, fieldSamples int, missing []string) string {
	if len(refs) == 0 {
		return "no_input_refs"
	}
	if fieldSamples == 0 {
		return "missing_samples"
	}
	if len(missing) > 0 {
		return "missing_fields"
	}
	return "verified"
}

func indexCoverageCatalog(specs []CoverageCatalogSpec) map[string]CoverageCatalogSpec {
	index := map[string]CoverageCatalogSpec{}
	for _, spec := range specs {
		for _, value := range []string{spec.Type, spec.Normalized} {
			key := normalizeResourceKey(value)
			if key == "" {
				continue
			}
			if spec.Normalized == "" {
				spec.Normalized = key
			}
			index[key] = spec
		}
	}
	return index
}

func normalizeBoolSet(values map[string]bool) map[string]bool {
	normalized := map[string]bool{}
	for value, enabled := range values {
		if !enabled {
			continue
		}
		key := normalizeResourceKey(value)
		if key != "" {
			normalized[key] = true
		}
	}
	return normalized
}

func cleanProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	provider = strings.ReplaceAll(provider, "_", "")
	provider = strings.ReplaceAll(provider, "-", "")
	provider = strings.ReplaceAll(provider, " ", "")
	if provider == "alicloud" || provider == "aliyun" {
		return "alicloud"
	}
	return provider
}

func cleanResourceType(resourceType string) string {
	resourceType = strings.TrimSpace(resourceType)
	if resourceType == "" {
		return "unknown"
	}
	return resourceType
}

func normalizeResourceKey(resourceType string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(resourceType)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
