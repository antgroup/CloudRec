package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/rule"
)

type scanQualityResponse struct {
	Summary scanQualitySummary `json:"summary"`
	Runs    []scanQualityRun   `json:"runs"`
	Count   int                `json:"count"`
	Total   int                `json:"total"`
	Limit   int                `json:"limit,omitempty"`
	Offset  int                `json:"offset,omitempty"`
}

type scanQualitySummary struct {
	TotalRuns           int                       `json:"total_runs"`
	SucceededRuns       int                       `json:"succeeded_runs"`
	FailedRuns          int                       `json:"failed_runs"`
	RunningRuns         int                       `json:"running_runs"`
	AssetsCollected     int                       `json:"assets_collected"`
	Findings            int                       `json:"findings"`
	Rules               int                       `json:"rules"`
	EvaluatedRules      int                       `json:"evaluated_rules"`
	SkippedRules        int                       `json:"skipped_rules"`
	CollectionFailures  int                       `json:"collection_failures"`
	EvaluationCoverage  float64                   `json:"evaluation_coverage"`
	CollectionHealth    string                    `json:"collection_health"`
	RuleQualityStatus   string                    `json:"rule_quality_status,omitempty"`
	RuleQuality         *rule.CoverageTotals      `json:"rule_quality,omitempty"`
	FailureCategories   map[string]int            `json:"failure_categories"`
	FailedResourceTypes []scanQualityFacet        `json:"failed_resource_types,omitempty"`
	ResourceTypes       []scanQualityResourceType `json:"resource_type_drilldown,omitempty"`
	LatestRun           *scanQualityRun           `json:"latest_run,omitempty"`
}

type scanQualityRun struct {
	ID                  string                    `json:"id"`
	AccountID           string                    `json:"account_id"`
	Provider            string                    `json:"provider"`
	Status              string                    `json:"status"`
	StartedAt           string                    `json:"started_at,omitempty"`
	FinishedAt          string                    `json:"finished_at,omitempty"`
	Assets              int                       `json:"assets"`
	Findings            int                       `json:"findings"`
	Rules               int                       `json:"rules"`
	EvaluatedRules      int                       `json:"evaluated_rules"`
	SkippedRules        int                       `json:"skipped_rules"`
	CollectionFailures  int                       `json:"collection_failures"`
	FailureCategories   map[string]int            `json:"failure_categories,omitempty"`
	FailedResourceTypes []scanQualityFacet        `json:"failed_resource_types,omitempty"`
	ResourceTypes       []scanQualityResourceType `json:"resource_type_drilldown,omitempty"`
	FailureItems        []scanCollectionFailure   `json:"failure_items,omitempty"`
	QualityStatus       string                    `json:"quality_status"`
}

type scanQualityFacet struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type scanQualityResourceType struct {
	ResourceType string             `json:"resource_type"`
	Status       string             `json:"status"`
	Failures     int                `json:"failures"`
	Categories   map[string]int     `json:"categories,omitempty"`
	Regions      []scanQualityFacet `json:"regions,omitempty"`
	Hint         string             `json:"hint,omitempty"`
}

type scanCollectionFailure struct {
	ResourceType string `json:"resource_type,omitempty"`
	Region       string `json:"region,omitempty"`
	Category     string `json:"category,omitempty"`
	Message      string `json:"message,omitempty"`
}

func (h *handler) scanQuality(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseScanRunFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	runs, err := h.store.ListScanRuns(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list scan quality runs failed")
		return
	}
	if runs == nil {
		runs = []model.ScanRun{}
	}
	total := len(runs)
	if counter, ok := h.store.(countScanRunsGetter); ok {
		if count, err := counter.CountScanRuns(r.Context(), filter); err == nil {
			total = count
		}
	}
	response := buildScanQualityResponse(runs, total, filter.Limit, filter.Offset)
	h.enrichScanQualityWithRules(&response)
	writeJSON(w, http.StatusOK, response)
}

func (h *handler) enrichScanQualityWithRules(response *scanQualityResponse) {
	if response == nil || strings.TrimSpace(h.rulesDir) == "" {
		return
	}
	if err := ValidateRulesDir(h.rulesDir); err != nil {
		response.Summary.RuleQualityStatus = "rules_unavailable"
		return
	}
	options := coverageOptions(h.rulesDir, h.provider)
	options.ReviewLedgerPath = defaultReviewLedgerPath(h.rulesDir)
	options.SamplesDir = defaultSamplesDir(h.rulesDir, h.provider)
	report, err := rule.AnalyzeCoverage(options)
	if err != nil {
		response.Summary.RuleQualityStatus = "rules_unavailable"
		return
	}
	response.Summary.RuleQuality = &report.Totals
	response.Summary.RuleQualityStatus = scanRuleQualityStatus(report.Totals)
}

func scanRuleQualityStatus(totals rule.CoverageTotals) string {
	if totals.MissingDataRefs > 0 || totals.MissingSampleRefs > 0 || totals.MissingSampleGroups > 0 {
		return "missing_fields"
	}
	if totals.MissingRemediation > 0 {
		return "missing_remediation"
	}
	if totals.NeedsLogicChange > 0 {
		return "needs_logic_change"
	}
	if totals.NeedsOfficialDocs > 0 || totals.NeedsReview > 0 {
		return "needs_review"
	}
	if totals.Blocked > 0 {
		return "blocked"
	}
	return "verified"
}

func buildScanQualityResponse(runs []model.ScanRun, total int, limit int, offset int) scanQualityResponse {
	qualityRuns := make([]scanQualityRun, 0, len(runs))
	for _, run := range runs {
		qualityRuns = append(qualityRuns, scanQualityRunFromModel(run))
	}
	summary := summarizeScanQuality(qualityRuns)
	return scanQualityResponse{
		Summary: summary,
		Runs:    qualityRuns,
		Count:   len(qualityRuns),
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}
}

func scanQualityRunFromModel(run model.ScanRun) scanQualityRun {
	summary := scanSummaryMap(run.Summary)
	failures := scanFailureItems(summary["collection_failure_items"])
	failureCategories := map[string]int{}
	failedTypes := map[string]int{}
	resourceTypes := map[string]*scanQualityResourceType{}
	for _, failure := range failures {
		category := strings.TrimSpace(failure.Category)
		if category == "" {
			category = "unknown"
		}
		failureCategories[category]++
		resourceType := strings.TrimSpace(failure.ResourceType)
		if resourceType != "" {
			failedTypes[resourceType]++
			entry := resourceTypes[resourceType]
			if entry == nil {
				entry = &scanQualityResourceType{
					ResourceType: resourceType,
					Status:       "failed",
					Categories:   map[string]int{},
				}
				resourceTypes[resourceType] = entry
			}
			entry.Failures++
			entry.Categories[category]++
		}
	}
	collectionFailures := intFromSummary(summary, "collection_failures")
	if collectionFailures == 0 && len(failures) > 0 {
		collectionFailures = len(failures)
	}
	qualityStatus := "complete"
	if run.Status == model.ScanRunStatusFailed {
		qualityStatus = "failed"
	} else if collectionFailures > 0 {
		qualityStatus = "partial"
	} else if intFromSummary(summary, "assets") == 0 && run.Status == model.ScanRunStatusSucceeded {
		qualityStatus = "empty"
	}

	quality := scanQualityRun{
		ID:                  run.ID,
		AccountID:           run.AccountID,
		Provider:            run.Provider,
		Status:              run.Status,
		StartedAt:           formatScanQualityTime(run.StartedAt),
		Assets:              intFromSummary(summary, "assets"),
		Findings:            intFromSummary(summary, "findings"),
		Rules:               intFromSummary(summary, "rules"),
		EvaluatedRules:      intFromSummary(summary, "evaluated_rules"),
		SkippedRules:        intFromSummary(summary, "skipped_rules"),
		CollectionFailures:  collectionFailures,
		FailureCategories:   failureCategories,
		FailedResourceTypes: sortedScanQualityFacets(failedTypes),
		ResourceTypes:       sortedScanQualityResourceTypes(resourceTypes),
		FailureItems:        failures,
		QualityStatus:       qualityStatus,
	}
	if run.FinishedAt != nil {
		quality.FinishedAt = formatScanQualityTime(*run.FinishedAt)
	}
	return quality
}

func summarizeScanQuality(runs []scanQualityRun) scanQualitySummary {
	summary := scanQualitySummary{
		TotalRuns:         len(runs),
		FailureCategories: map[string]int{},
	}
	failedResourceTypes := map[string]int{}
	resourceTypes := map[string]*scanQualityResourceType{}
	for i, run := range runs {
		if i == 0 {
			latest := run
			summary.LatestRun = &latest
		}
		switch run.Status {
		case model.ScanRunStatusSucceeded:
			summary.SucceededRuns++
		case model.ScanRunStatusFailed:
			summary.FailedRuns++
		case model.ScanRunStatusRunning:
			summary.RunningRuns++
		}
		summary.AssetsCollected += run.Assets
		summary.Findings += run.Findings
		summary.Rules += run.Rules
		summary.EvaluatedRules += run.EvaluatedRules
		summary.SkippedRules += run.SkippedRules
		summary.CollectionFailures += run.CollectionFailures
		for category, count := range run.FailureCategories {
			summary.FailureCategories[category] += count
		}
		for _, item := range run.FailedResourceTypes {
			failedResourceTypes[item.Value] += item.Count
		}
		mergeScanQualityResourceTypes(resourceTypes, run.ResourceTypes)
	}
	if summary.EvaluatedRules+summary.SkippedRules > 0 {
		summary.EvaluationCoverage = float64(summary.EvaluatedRules) / float64(summary.EvaluatedRules+summary.SkippedRules)
	}
	summary.FailedResourceTypes = sortedScanQualityFacets(failedResourceTypes)
	summary.ResourceTypes = sortedScanQualityResourceTypes(resourceTypes)
	summary.CollectionHealth = "complete"
	if summary.FailedRuns > 0 {
		summary.CollectionHealth = "failed"
	} else if summary.CollectionFailures > 0 {
		summary.CollectionHealth = "partial"
	} else if summary.TotalRuns == 0 || summary.AssetsCollected == 0 {
		summary.CollectionHealth = "empty"
	}
	return summary
}

func scanSummaryMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var summary map[string]any
	if err := json.Unmarshal(raw, &summary); err != nil {
		return map[string]any{}
	}
	return summary
}

func scanFailureItems(value any) []scanCollectionFailure {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var failures []scanCollectionFailure
	if err := json.Unmarshal(raw, &failures); err == nil {
		return failures
	}
	return nil
}

func intFromSummary(summary map[string]any, key string) int {
	switch value := summary[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		n, _ := value.Int64()
		return int(n)
	default:
		return 0
	}
}

func sortedScanQualityFacets(values map[string]int) []scanQualityFacet {
	facets := make([]scanQualityFacet, 0, len(values))
	for value, count := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		facets = append(facets, scanQualityFacet{Value: value, Count: count})
	}
	sort.Slice(facets, func(i, j int) bool {
		if facets[i].Count != facets[j].Count {
			return facets[i].Count > facets[j].Count
		}
		return facets[i].Value < facets[j].Value
	})
	return facets
}

func mergeScanQualityResourceTypes(target map[string]*scanQualityResourceType, values []scanQualityResourceType) {
	for _, value := range values {
		resourceType := strings.TrimSpace(value.ResourceType)
		if resourceType == "" {
			continue
		}
		entry := target[resourceType]
		if entry == nil {
			entry = &scanQualityResourceType{
				ResourceType: resourceType,
				Status:       value.Status,
				Categories:   map[string]int{},
			}
			target[resourceType] = entry
		}
		entry.Failures += value.Failures
		for category, count := range value.Categories {
			entry.Categories[category] += count
		}
	}
}

func sortedScanQualityResourceTypes(values map[string]*scanQualityResourceType) []scanQualityResourceType {
	result := make([]scanQualityResourceType, 0, len(values))
	for _, value := range values {
		if value == nil || strings.TrimSpace(value.ResourceType) == "" {
			continue
		}
		value.Hint = scanQualityHint(value.Categories)
		if value.Status == "" {
			value.Status = "failed"
		}
		result = append(result, *value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Failures != result[j].Failures {
			return result[i].Failures > result[j].Failures
		}
		return result[i].ResourceType < result[j].ResourceType
	})
	return result
}

func scanQualityHint(categories map[string]int) string {
	if len(categories) == 0 {
		return "Review collector logs and rerun with --collector-log-level debug if needed."
	}
	switch dominantScanQualityCategory(categories) {
	case "permission", "forbidden", "credential":
		return "Grant the missing read-only RAM permissions or use the minimum policy hint before trusting this resource type."
	case "timeout":
		return "Increase --collector-timeout or scan this resource type separately."
	case "throttling", "rate_limit", "ratelimit":
		return "Reduce concurrency or retry after API throttling cools down."
	case "unsupported":
		return "This product is not covered by the current Lite collector path."
	case "not_enabled", "product_not_enabled", "not_open":
		return "The product appears disabled in this account or region; confirm it is expected."
	default:
		return "Review the failure message and rerun the scan after fixing the resource-type issue."
	}
}

func dominantScanQualityCategory(categories map[string]int) string {
	bestCategory := "unknown"
	bestCount := -1
	for category, count := range categories {
		normalized := strings.ToLower(strings.TrimSpace(category))
		if normalized == "" {
			normalized = "unknown"
		}
		if count > bestCount || (count == bestCount && normalized < bestCategory) {
			bestCategory = normalized
			bestCount = count
		}
	}
	return bestCategory
}

func formatScanQualityTime(value interface{ Format(string) string }) string {
	return value.Format("2006-01-02T15:04:05Z07:00")
}
