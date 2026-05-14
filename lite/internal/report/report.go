package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/antgroup/CloudRec/lite/internal/core"
	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/provider"
)

const (
	FormatText = "text"
	FormatJSON = "json"
)

type scanResultJSON struct {
	Provider               string                       `json:"provider"`
	Account                string                       `json:"account"`
	RuleCount              int                          `json:"rule_count"`
	AssetCount             int                          `json:"asset_count"`
	AddedAssetCount        int                          `json:"added_asset_count"`
	UpdatedAssetCount      int                          `json:"updated_asset_count"`
	MissingAssetCount      int                          `json:"missing_asset_count"`
	SeenAssetCount         int                          `json:"seen_asset_count"`
	FindingCount           int                          `json:"finding_count"`
	EvaluatedRuleCount     int                          `json:"evaluated_rule_count"`
	SkippedRuleCount       int                          `json:"skipped_rule_count"`
	CollectionFailureCount int                          `json:"collection_failure_count"`
	CollectionFailures     []provider.CollectionFailure `json:"collection_failures,omitempty"`
	CollectionTaskSummary  *model.ScanTaskSummary       `json:"collection_task_summary,omitempty"`
	DryRun                 bool                         `json:"dry_run"`
	ScanRunID              string                       `json:"scan_run_id,omitempty"`
}

func RenderScanResult(w io.Writer, result core.ScanResult, format string) error {
	if w == nil {
		return errors.New("report writer is required")
	}

	switch normalizeFormat(format) {
	case "", FormatText:
		return renderScanResultText(w, result)
	case FormatJSON:
		return renderScanResultJSON(w, result)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func renderScanResultText(w io.Writer, result core.ScanResult) error {
	_, err := fmt.Fprintf(w, "scan completed: provider=%s account=%s assets=%d addedAssets=%d updatedAssets=%d missingAssets=%d seenAssets=%d findings=%d rules=%d evaluatedRules=%d skippedRules=%d collectionFailures=%d collectionTasks=%d skippedTasks=%d dryRun=%t\n",
		result.Provider,
		result.Account,
		result.AssetCount,
		result.AddedAssetCount,
		result.UpdatedAssetCount,
		result.MissingAssetCount,
		result.SeenAssetCount,
		result.FindingCount,
		result.RuleCount,
		result.EvaluatedRuleCount,
		result.SkippedRuleCount,
		result.CollectionFailureCount,
		result.CollectionTaskSummary.Total,
		result.CollectionTaskSummary.Skipped,
		result.DryRun,
	)
	return err
}

func renderScanResultJSON(w io.Writer, result core.ScanResult) error {
	var taskSummary *model.ScanTaskSummary
	if result.CollectionTaskSummary.Total > 0 {
		taskSummary = &result.CollectionTaskSummary
	}
	payload := scanResultJSON{
		Provider:               result.Provider,
		Account:                result.Account,
		RuleCount:              result.RuleCount,
		AssetCount:             result.AssetCount,
		AddedAssetCount:        result.AddedAssetCount,
		UpdatedAssetCount:      result.UpdatedAssetCount,
		MissingAssetCount:      result.MissingAssetCount,
		SeenAssetCount:         result.SeenAssetCount,
		FindingCount:           result.FindingCount,
		EvaluatedRuleCount:     result.EvaluatedRuleCount,
		SkippedRuleCount:       result.SkippedRuleCount,
		CollectionFailureCount: result.CollectionFailureCount,
		CollectionFailures:     result.CollectionFailures,
		CollectionTaskSummary:  taskSummary,
		DryRun:                 result.DryRun,
		ScanRunID:              result.ScanRunID,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func normalizeFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}
