package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/collectorstate"
	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/progress"
	"github.com/antgroup/CloudRec/lite/internal/provider"
	"github.com/antgroup/CloudRec/lite/internal/rule"
	"github.com/antgroup/CloudRec/lite/internal/storage"
	"github.com/antgroup/CloudRec/lite/providers/alicloud"
	"github.com/antgroup/CloudRec/lite/providers/mock"
)

const (
	defaultAppDir     = "cloudrec-lite"
	defaultDBFileName = "cloudrec-lite.db"
)

func DefaultDBPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(configDir) == "" {
		return filepath.Join(os.TempDir(), defaultDBFileName)
	}
	return filepath.Join(configDir, defaultAppDir, defaultDBFileName)
}

func NormalizeDBPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return DefaultDBPath()
	}
	return path
}

func EnsureDBParentDir(path string) error {
	path = NormalizeDBPath(path)
	parent := filepath.Dir(path)
	if parent == "" || parent == "." {
		return nil
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create database parent %q: %w", parent, err)
	}
	return nil
}

const defaultCollectorSkipCacheTTL = 24 * time.Hour

type ScanOptions struct {
	Provider    string
	Account     string
	Region      string
	RulesDir    string
	DBPath      string
	DryRun      bool
	Credentials map[string]string
	Config      map[string]string
	Progress    io.Writer
}

type ScanResult struct {
	Provider               string
	Account                string
	RuleCount              int
	AssetCount             int
	AddedAssetCount        int
	UpdatedAssetCount      int
	MissingAssetCount      int
	SeenAssetCount         int
	FindingCount           int
	EvaluatedRuleCount     int
	SkippedRuleCount       int
	CollectionFailureCount int
	CollectionFailures     []provider.CollectionFailure
	CollectionTaskSummary  model.ScanTaskSummary
	DryRun                 bool
	ScanRunID              string
}

type Scanner struct {
	providers map[string]provider.Provider
	evaluator rule.Evaluator
}

func NewScanner() *Scanner {
	scanner := &Scanner{
		providers: map[string]provider.Provider{},
		evaluator: rule.NewEvaluator(rule.NewOPAEngine()),
	}
	scanner.RegisterProvider(alicloud.New())
	scanner.RegisterProvider(mock.New())
	return scanner
}

func (s *Scanner) RegisterProvider(provider provider.Provider) {
	if provider == nil {
		return
	}
	s.providers[provider.Name()] = provider
}

func (s *Scanner) Scan(options ScanOptions) (ScanResult, error) {
	return s.ScanContext(context.Background(), options)
}

func (s *Scanner) ScanContext(ctx context.Context, options ScanOptions) (ScanResult, error) {
	reporter := progress.FromContext(ctx)
	if reporter == nil && options.Progress != nil {
		reporter = progress.NewReporter(options.Progress)
		ctx = progress.WithReporter(ctx, reporter)
	}
	if reporter == nil {
		reporter = progress.NewReporter(io.Discard)
		ctx = progress.WithReporter(ctx, reporter)
	}
	scanStageEvaluate := "evaluate rules"
	scanStages := []string{
		"validate account",
		"load rules",
	}
	if !options.DryRun {
		scanStageEvaluate = "evaluate rules and store results"
		scanStages = append(scanStages, "prepare storage")
	}
	scanStages = append(scanStages, "collect assets")
	scanStages = append(scanStages, scanStageEvaluate)
	scanTracker := reporter.Tracker("scan", scanStages)
	scanTracker.Start()

	providerName := strings.TrimSpace(options.Provider)
	if providerName == "" {
		return ScanResult{}, errors.New("scan provider is required")
	}

	accountID := strings.TrimSpace(options.Account)
	if accountID == "" {
		return ScanResult{}, errors.New("scan account is required")
	}

	cloudProvider, ok := s.providers[providerName]
	if !ok {
		return ScanResult{}, fmt.Errorf("provider %q is not registered", providerName)
	}

	account := provider.Account{
		Provider:      providerName,
		AccountID:     accountID,
		DefaultRegion: strings.TrimSpace(options.Region),
		Credentials:   cloneStringMap(options.Credentials),
		Config:        cloneStringMap(options.Config),
	}
	started := time.Now()
	scanTracker.TaskStart("validate account")
	if err := cloudProvider.ValidateAccount(ctx, account); err != nil {
		scanTracker.TaskDone("validate account", err, time.Since(started))
		return ScanResult{}, fmt.Errorf("validate account: %w", err)
	}
	scanTracker.TaskDone("validate account", nil, time.Since(started))

	started = time.Now()
	scanTracker.TaskStart("load rules")
	rulesDir, err := resolveRulesDir(options.RulesDir)
	if err != nil {
		scanTracker.TaskDone("load rules", err, time.Since(started))
		return ScanResult{}, err
	}
	rulePacks, err := rule.LoadDir(rulesDir)
	if err != nil {
		scanTracker.TaskDone("load rules", err, time.Since(started))
		return ScanResult{}, err
	}
	scanTracker.TaskDone("load rules", nil, time.Since(started))

	result := ScanResult{
		Provider:  providerName,
		Account:   accountID,
		RuleCount: len(rulePacks),
		DryRun:    options.DryRun,
	}

	var store *storage.SQLiteStore
	var scanRun model.ScanRun
	previousAssets := map[string]model.Asset{}
	seenAssetKeys := map[string]bool{}
	trackedResourceTypes := selectedResourceTypeSet(account.Config)
	if !options.DryRun {
		started = time.Now()
		scanTracker.TaskStart("prepare storage")
		dbPath := NormalizeDBPath(options.DBPath)
		if err := EnsureDBParentDir(dbPath); err != nil {
			scanTracker.TaskDone("prepare storage", err, time.Since(started))
			return ScanResult{}, err
		}

		store, err = storage.Open(ctx, dbPath)
		if err != nil {
			scanTracker.TaskDone("prepare storage", err, time.Since(started))
			return ScanResult{}, err
		}
		defer store.Close()

		if err := store.Init(ctx); err != nil {
			scanTracker.TaskDone("prepare storage", err, time.Since(started))
			return ScanResult{}, err
		}

		if _, err := store.UpsertAccount(ctx, model.Account{
			ID:         accountID,
			Provider:   providerName,
			Name:       accountID,
			ExternalID: accountID,
		}); err != nil {
			scanTracker.TaskDone("prepare storage", err, time.Since(started))
			return ScanResult{}, err
		}

		existingAssets, err := store.ListAssets(ctx, storage.AssetFilter{
			AccountID: accountID,
		})
		if err != nil {
			scanTracker.TaskDone("prepare storage", err, time.Since(started))
			return ScanResult{}, err
		}
		for _, existingAsset := range existingAssets {
			if len(trackedResourceTypes) > 0 && !trackedResourceTypes[normalizeAssetType(existingAsset.ResourceType)] {
				continue
			}
			previousAssets[assetKey(existingAsset.ResourceType, existingAsset.ResourceID)] = existingAsset
		}

		skipCacheTTL, err := collectorSkipCacheTTL(account.Config)
		if err != nil {
			scanTracker.TaskDone("prepare storage", err, time.Since(started))
			return ScanResult{}, err
		}
		scanRun, err = store.CreateScanRun(ctx, model.ScanRun{
			AccountID: accountID,
			Provider:  providerName,
		})
		if err != nil {
			scanTracker.TaskDone("prepare storage", err, time.Since(started))
			return ScanResult{}, err
		}
		result.ScanRunID = scanRun.ID
		if skipCacheTTL > 0 {
			entries, err := store.ListActiveCollectorSkipEntries(ctx, providerName, accountID, time.Now().UTC())
			if err != nil {
				_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
				scanTracker.TaskDone("prepare storage", err, time.Since(started))
				return ScanResult{}, err
			}
			ctx = collectorstate.WithSkipCache(ctx, collectorstate.NewSkipCache(providerName, accountID, skipCacheTTL, collectorSkipEntries(entries)))
		}
		scanTracker.TaskDone("prepare storage", nil, time.Since(started))
	}

	recorder := collectorstate.NewRecorder(providerName, accountID)
	ctx = collectorstate.WithRecorder(ctx, recorder)

	started = time.Now()
	scanTracker.TaskStart("collect assets")
	assets, err := cloudProvider.CollectAssets(ctx, account)
	collectErr := err
	if err != nil {
		var partial *provider.PartialCollectionError
		if errors.As(err, &partial) {
			assets = partial.Assets
		}
	}
	result.AssetCount = len(assets)
	result.CollectionFailures = collectionFailures(err)
	result.CollectionFailureCount = len(result.CollectionFailures)
	result.CollectionTaskSummary = modelScanTaskSummary(collectorstate.Summarize(recorder.Snapshot()))
	for i := range assets {
		assets[i].AccountID = firstNonEmptyValue(assets[i].AccountID, accountID)
		assets[i].Provider = firstNonEmptyValue(assets[i].Provider, providerName)
	}
	linkedAssets := newLinkedAssetResolver(assets)

	if store != nil {
		if persistErr := persistCollectionState(ctx, store, scanRun.ID, recorder, collectorstate.SkipCacheFromContext(ctx)); persistErr != nil {
			_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
			scanTracker.TaskDone("collect assets", persistErr, time.Since(started))
			return ScanResult{}, persistErr
		}
	}
	if err != nil {
		var partial *provider.PartialCollectionError
		if !errors.As(err, &partial) {
			if store != nil {
				_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
			}
			scanTracker.TaskDone("collect assets", err, time.Since(started))
			return ScanResult{}, fmt.Errorf("collect assets: %w", err)
		}
	}
	scanTracker.TaskDone("collect assets", collectErr, time.Since(started))

	evaluateStarted := time.Now()
	scanTracker.TaskStart(scanStageEvaluate)
	assetTasks := assetProgressTasks(assets)
	assetTracker := reporter.Tracker(scanStageEvaluate, assetTasks)
	assetTracker.Start()
	for _, asset := range assets {
		assetStarted := time.Now()
		assetTask := assetProgressTask(asset)
		assetTracker.TaskStart(assetTask)
		asset.AccountID = accountID
		if asset.Provider == "" {
			asset.Provider = providerName
		}

		matchingRulePacks := filterRulePacks(rulePacks, asset.Provider, asset.Type)
		ruleInput := assetRuleInput(asset)
		applyLinkedRuleInputs(ruleInput, asset, matchingRulePacks, linkedAssets)
		findings, evaluatedRuleCount, err := s.evaluateAsset(ctx, matchingRulePacks, ruleInput)
		if err != nil {
			assetTracker.TaskDone(assetTask, err, time.Since(assetStarted))
			scanTracker.TaskDone(scanStageEvaluate, err, time.Since(evaluateStarted))
			return ScanResult{}, err
		}
		result.FindingCount += len(findings)
		result.EvaluatedRuleCount += evaluatedRuleCount
		result.SkippedRuleCount += len(rulePacks) - evaluatedRuleCount

		if options.DryRun {
			assetTracker.TaskDone(assetTask, nil, time.Since(assetStarted))
			continue
		}

		assetModel := modelAsset(asset)
		key := assetKey(assetModel.ResourceType, assetModel.ResourceID)
		previousAsset, existed := previousAssets[key]
		seenAssetKeys[key] = true

		storedAsset, err := store.UpsertAsset(ctx, assetModel)
		if err != nil {
			_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
			assetTracker.TaskDone(assetTask, err, time.Since(assetStarted))
			scanTracker.TaskDone(scanStageEvaluate, err, time.Since(evaluateStarted))
			return ScanResult{}, err
		}

		scanStatus := model.AssetScanStatusAdded
		if existed {
			scanStatus = model.AssetScanStatusSeen
			result.SeenAssetCount++
			if assetChanged(previousAsset, assetModel) {
				scanStatus = model.AssetScanStatusUpdated
				result.SeenAssetCount--
				result.UpdatedAssetCount++
			}
		} else {
			result.AddedAssetCount++
		}
		if _, err := store.UpsertAssetScanState(ctx, model.AssetScanState{
			ScanRunID:    scanRun.ID,
			AccountID:    accountID,
			AssetID:      storedAsset.ID,
			ResourceType: storedAsset.ResourceType,
			ResourceID:   storedAsset.ResourceID,
			Status:       scanStatus,
		}); err != nil {
			_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
			assetTracker.TaskDone(assetTask, err, time.Since(assetStarted))
			scanTracker.TaskDone(scanStageEvaluate, err, time.Since(evaluateStarted))
			return ScanResult{}, err
		}

		for _, relationship := range asset.Relationships {
			if strings.TrimSpace(relationship.Type) == "" || strings.TrimSpace(relationship.TargetID) == "" {
				continue
			}
			if _, err := store.UpsertAssetRelationship(ctx, modelAssetRelationship(storedAsset, relationship)); err != nil {
				_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
				assetTracker.TaskDone(assetTask, err, time.Since(assetStarted))
				scanTracker.TaskDone(scanStageEvaluate, err, time.Since(evaluateStarted))
				return ScanResult{}, err
			}
		}

		for _, finding := range findings {
			if _, err := store.UpsertFinding(ctx, modelFinding(scanRun.ID, accountID, storedAsset.ID, finding)); err != nil {
				_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
				assetTracker.TaskDone(assetTask, err, time.Since(assetStarted))
				scanTracker.TaskDone(scanStageEvaluate, err, time.Since(evaluateStarted))
				return ScanResult{}, err
			}
		}
		assetTracker.TaskDone(assetTask, nil, time.Since(assetStarted))
	}
	assetTracker.Finish("finished")

	if !options.DryRun {
		for key, previousAsset := range previousAssets {
			if seenAssetKeys[key] {
				continue
			}
			result.MissingAssetCount++
			if _, err := store.UpsertAssetScanState(ctx, model.AssetScanState{
				ScanRunID:    scanRun.ID,
				AccountID:    accountID,
				AssetID:      previousAsset.ID,
				ResourceType: previousAsset.ResourceType,
				ResourceID:   previousAsset.ResourceID,
				Status:       model.AssetScanStatusMissing,
			}); err != nil {
				_ = finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusFailed, result)
				scanTracker.TaskDone(scanStageEvaluate, err, time.Since(evaluateStarted))
				return ScanResult{}, err
			}
		}
		if err := finishScanRun(ctx, store, scanRun.ID, model.ScanRunStatusSucceeded, result); err != nil {
			scanTracker.TaskDone(scanStageEvaluate, err, time.Since(evaluateStarted))
			return ScanResult{}, err
		}
	}
	scanTracker.TaskDone(scanStageEvaluate, nil, time.Since(evaluateStarted))
	scanTracker.Finish("finished")

	return result, nil
}

func (s *Scanner) evaluateAsset(ctx context.Context, packs []rule.RulePack, input map[string]any) ([]rule.FindingResult, int, error) {
	filtered := filterRulePacks(packs, stringValue(input["provider"]), stringValue(input["type"]))
	findings, err := s.evaluator.Evaluate(ctx, filtered, input)
	if err != nil {
		return nil, len(filtered), err
	}

	for i := range findings {
		if findings[i].AssetID == "" {
			findings[i].AssetID = stringValue(input["id"])
		}
		if findings[i].AccountID == "" {
			findings[i].AccountID = stringValue(input["account_id"])
		}
		if findings[i].Provider == "" {
			findings[i].Provider = stringValue(input["provider"])
		}
		if findings[i].Region == "" {
			findings[i].Region = stringValue(input["region"])
		}
		if findings[i].AssetType == "" {
			findings[i].AssetType = stringValue(input["type"])
		}
	}
	return findings, len(filtered), nil
}

func collectionFailures(err error) []provider.CollectionFailure {
	var partial *provider.PartialCollectionError
	if !errors.As(err, &partial) || partial == nil {
		return nil
	}
	return append([]provider.CollectionFailure(nil), partial.Failures...)
}

func filterRulePacks(packs []rule.RulePack, providerName string, assetType string) []rule.RulePack {
	providerName = normalizeProviderName(providerName)
	assetType = normalizeAssetType(assetType)

	filtered := make([]rule.RulePack, 0, len(packs))
	for _, pack := range packs {
		if pack.Metadata.Provider != "" && normalizeProviderName(pack.Metadata.Provider) != providerName {
			continue
		}
		if pack.Metadata.AssetType != "" && normalizeAssetType(pack.Metadata.AssetType) != assetType {
			continue
		}
		filtered = append(filtered, pack)
	}
	return filtered
}

func assetRuleInput(asset provider.Asset) map[string]any {
	input := copyMap(asset.Properties)
	input["id"] = asset.ID
	input["name"] = asset.Name
	input["provider"] = asset.Provider
	input["account_id"] = asset.AccountID
	input["region"] = asset.Region
	input["type"] = normalizeAssetType(asset.Type)
	input["raw_type"] = asset.Type
	input["tags"] = asset.Tags
	input["attributes"] = copyMap(asset.Properties)
	input["relationships"] = relationshipInputs(asset.Relationships)
	return input
}

type linkedAssetResolver struct {
	assetsByType map[string][]provider.Asset
}

func newLinkedAssetResolver(assets []provider.Asset) linkedAssetResolver {
	resolver := linkedAssetResolver{
		assetsByType: map[string][]provider.Asset{},
	}
	for _, asset := range assets {
		assetType := normalizeAssetType(asset.Type)
		if assetType == "" {
			continue
		}
		resolver.assetsByType[assetType] = append(resolver.assetsByType[assetType], asset)
	}
	return resolver
}

func applyLinkedRuleInputs(input map[string]any, asset provider.Asset, packs []rule.RulePack, resolver linkedAssetResolver) {
	if len(packs) == 0 || len(resolver.assetsByType) == 0 {
		return
	}
	for _, pack := range packs {
		for _, spec := range pack.Metadata.LinkedData {
			key := strings.TrimSpace(spec.NewKeyName)
			if key == "" || inputHasMeaningfulValue(input[key]) {
				continue
			}
			if value, ok := resolver.resolve(asset, spec); ok {
				input[key] = value
			}
		}
	}
}

func (r linkedAssetResolver) resolve(source provider.Asset, spec rule.LinkedDataSpec) (any, bool) {
	sourceValues := jsonPathStringValues(source.Properties, spec.LinkedKey1)
	if len(sourceValues) == 0 {
		return nil, false
	}
	sourceSet := map[string]bool{}
	for _, value := range sourceValues {
		sourceSet[value] = true
	}

	var matches []any
	for _, targetType := range linkedTargetTypes(spec.ResourceType) {
		for _, target := range r.assetsByType[targetType] {
			if !sameAssetScope(source, target) {
				continue
			}
			for _, targetValue := range jsonPathStringValues(target.Properties, spec.LinkedKey2) {
				if sourceSet[targetValue] {
					matches = append(matches, copyMap(target.Properties))
					break
				}
			}
		}
	}
	if len(matches) == 0 {
		return nil, false
	}
	if shouldUseSingleLinkedValue(spec, len(matches)) {
		return matches[0], true
	}
	return matches, true
}

func sameAssetScope(source provider.Asset, target provider.Asset) bool {
	if source.AccountID != "" && target.AccountID != "" && source.AccountID != target.AccountID {
		return false
	}
	if source.Provider != "" && target.Provider != "" && normalizeProviderName(source.Provider) != normalizeProviderName(target.Provider) {
		return false
	}
	return true
}

func linkedTargetTypes(resourceTypes []string) []string {
	types := []string{}
	for i := len(resourceTypes) - 1; i >= 0; i-- {
		assetType := normalizeAssetType(resourceTypes[i])
		if assetType == "" {
			continue
		}
		types = append(types, assetType)
		break
	}
	return types
}

func shouldUseSingleLinkedValue(spec rule.LinkedDataSpec, matchCount int) bool {
	if matchCount != 1 {
		return false
	}
	return !strings.Contains(spec.LinkedKey1, "[*]")
}

func inputHasMeaningfulValue(value any) bool {
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func jsonPathStringValues(root any, path string) []string {
	values := jsonPathValues(root, path)
	output := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "<nil>" || seen[text] {
			continue
		}
		seen[text] = true
		output = append(output, text)
	}
	return output
}

func jsonPathValues(root any, path string) []any {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$.")
	if path == "" || path == "$" {
		return []any{root}
	}
	values := []any{root}
	for _, segment := range strings.Split(path, ".") {
		values = jsonPathStep(values, strings.TrimSpace(segment))
		if len(values) == 0 {
			return nil
		}
	}
	return values
}

func jsonPathStep(values []any, segment string) []any {
	if segment == "" {
		return nil
	}
	expandArray := false
	field := segment
	if strings.HasSuffix(field, "[*]") {
		expandArray = true
		field = strings.TrimSuffix(field, "[*]")
	}

	var output []any
	for _, value := range values {
		if field != "" {
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			value = object[field]
		}
		if !expandArray {
			if value != nil {
				output = append(output, value)
			}
			continue
		}
		switch typed := value.(type) {
		case []any:
			output = append(output, typed...)
		case []string:
			for _, item := range typed {
				output = append(output, item)
			}
		case nil:
		default:
			output = append(output, typed)
		}
	}
	return output
}

func normalizeAssetType(assetType string) string {
	assetType = strings.ToLower(strings.TrimSpace(assetType))
	var builder strings.Builder
	lastUnderscore := false
	for _, r := range assetType {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(builder.String(), "_")
}

func normalizeProviderName(providerName string) string {
	switch strings.ToLower(strings.TrimSpace(providerName)) {
	case "ali_cloud", "alibaba_cloud", "aliyun":
		return "alicloud"
	default:
		return strings.ToLower(strings.TrimSpace(providerName))
	}
}

func copyMap(input map[string]any) map[string]any {
	output := map[string]any{}
	for key, value := range input {
		output[key] = value
	}
	return output
}

func relationshipInputs(relationships []provider.Relationship) []map[string]any {
	output := make([]map[string]any, 0, len(relationships))
	for _, relationship := range relationships {
		output = append(output, map[string]any{
			"type":       relationship.Type,
			"target_id":  relationship.TargetID,
			"properties": copyMap(relationship.Properties),
		})
	}
	return output
}

func modelAsset(asset provider.Asset) model.Asset {
	properties, _ := json.Marshal(map[string]any{
		"attributes":    copyMap(asset.Properties),
		"tags":          asset.Tags,
		"relationships": relationshipInputs(asset.Relationships),
	})

	return model.Asset{
		AccountID:    asset.AccountID,
		Provider:     asset.Provider,
		ResourceType: asset.Type,
		ResourceID:   asset.ID,
		Region:       asset.Region,
		Name:         asset.Name,
		Properties:   properties,
	}
}

func modelAssetRelationship(asset model.Asset, relationship provider.Relationship) model.AssetRelationship {
	properties, _ := json.Marshal(relationship.Properties)
	return model.AssetRelationship{
		AccountID:          asset.AccountID,
		Provider:           asset.Provider,
		SourceAssetID:      asset.ID,
		SourceResourceType: asset.ResourceType,
		SourceResourceID:   asset.ResourceID,
		RelationshipType:   relationship.Type,
		TargetResourceID:   relationship.TargetID,
		Properties:         properties,
	}
}

func modelFinding(scanRunID string, accountID string, assetID string, finding rule.FindingResult) model.Finding {
	evidence, _ := json.Marshal(finding.Evidence)
	title := strings.TrimSpace(finding.Title)
	if title == "" {
		title = finding.RuleName
	}
	message := strings.TrimSpace(finding.Message)
	if message == "" {
		message = title
	}

	return model.Finding{
		ScanRunID:   scanRunID,
		AccountID:   accountID,
		AssetID:     assetID,
		RuleID:      finding.RuleID,
		Title:       title,
		Severity:    normalizeSeverity(finding.Severity),
		Status:      model.FindingStatusOpen,
		Message:     message,
		Evidence:    evidence,
		Remediation: finding.Remediation,
	}
}

func normalizeSeverity(severity rule.Severity) string {
	switch strings.ToLower(strings.TrimSpace(string(severity))) {
	case model.SeverityInfo:
		return model.SeverityInfo
	case model.SeverityLow:
		return model.SeverityLow
	case model.SeverityMedium:
		return model.SeverityMedium
	case model.SeverityHigh:
		return model.SeverityHigh
	case model.SeverityCritical:
		return model.SeverityCritical
	default:
		return model.SeverityUnknown
	}
}

func finishScanRun(ctx context.Context, store *storage.SQLiteStore, scanRunID string, status string, result ScanResult) error {
	summary, _ := json.Marshal(map[string]any{
		"rules":                    result.RuleCount,
		"assets":                   result.AssetCount,
		"added_assets":             result.AddedAssetCount,
		"updated_assets":           result.UpdatedAssetCount,
		"missing_assets":           result.MissingAssetCount,
		"seen_assets":              result.SeenAssetCount,
		"findings":                 result.FindingCount,
		"evaluated_rules":          result.EvaluatedRuleCount,
		"skipped_rules":            result.SkippedRuleCount,
		"collection_failures":      result.CollectionFailureCount,
		"collection_failure_items": result.CollectionFailures,
		"collection_task_summary":  result.CollectionTaskSummary,
	})
	_, err := store.FinishScanRun(ctx, scanRunID, status, summary)
	return err
}

func persistCollectionState(ctx context.Context, store *storage.SQLiteStore, scanRunID string, recorder *collectorstate.Recorder, skipCache *collectorstate.SkipCache) error {
	if store == nil {
		return nil
	}
	if records := recorder.Snapshot(); len(records) > 0 {
		if err := store.InsertScanTaskRuns(ctx, modelScanTaskRuns(records, scanRunID)); err != nil {
			return err
		}
	}
	if skipCache != nil {
		if err := store.UpsertCollectorSkipEntries(ctx, modelCollectorSkipEntries(skipCache.Observed())); err != nil {
			return err
		}
	}
	return nil
}

func modelScanTaskSummary(summary collectorstate.TaskSummary) model.ScanTaskSummary {
	return model.ScanTaskSummary{
		Total:      summary.Total,
		Succeeded:  summary.Succeeded,
		Failed:     summary.Failed,
		Skipped:    summary.Skipped,
		DurationMs: summary.DurationMs,
		Slowest:    modelScanTaskSummaryItems(summary.Slowest),
	}
}

func modelScanTaskSummaryItems(records []collectorstate.TaskRecord) []model.ScanTaskSummaryItem {
	items := make([]model.ScanTaskSummaryItem, 0, len(records))
	for _, record := range records {
		items = append(items, model.ScanTaskSummaryItem{
			Scope:        record.Scope,
			ResourceType: record.ResourceType,
			Region:       record.Region,
			Status:       record.Status,
			Category:     record.Category,
			Message:      record.Message,
			AssetCount:   record.AssetCount,
			DurationMs:   record.DurationMs,
		})
	}
	return items
}

func modelScanTaskRuns(records []collectorstate.TaskRecord, scanRunID string) []model.ScanTaskRun {
	tasks := make([]model.ScanTaskRun, 0, len(records))
	for _, record := range records {
		tasks = append(tasks, model.ScanTaskRun{
			ScanRunID:    scanRunID,
			AccountID:    record.AccountID,
			Provider:     record.Provider,
			Scope:        record.Scope,
			ResourceType: record.ResourceType,
			Region:       record.Region,
			Status:       record.Status,
			Category:     record.Category,
			Message:      record.Message,
			AssetCount:   record.AssetCount,
			Attempt:      record.Attempt,
			StartedAt:    record.StartedAt,
			FinishedAt:   record.FinishedAt,
			DurationMs:   record.DurationMs,
		})
	}
	return tasks
}

func collectorSkipEntries(entries []model.CollectorSkipEntry) []collectorstate.SkipEntry {
	values := make([]collectorstate.SkipEntry, 0, len(entries))
	for _, entry := range entries {
		values = append(values, collectorstate.SkipEntry{
			Provider:     entry.Provider,
			AccountID:    entry.AccountID,
			ResourceType: entry.ResourceType,
			Region:       entry.Region,
			Category:     entry.Category,
			Message:      entry.Message,
			ExpiresAt:    entry.ExpiresAt,
		})
	}
	return values
}

func modelCollectorSkipEntries(entries []collectorstate.SkipEntry) []model.CollectorSkipEntry {
	values := make([]model.CollectorSkipEntry, 0, len(entries))
	for _, entry := range entries {
		values = append(values, model.CollectorSkipEntry{
			AccountID:    entry.AccountID,
			Provider:     entry.Provider,
			ResourceType: entry.ResourceType,
			Region:       entry.Region,
			Category:     entry.Category,
			Message:      entry.Message,
			ExpiresAt:    entry.ExpiresAt,
		})
	}
	return values
}

func collectorSkipCacheTTL(config map[string]string) (time.Duration, error) {
	enabled := strings.ToLower(strings.TrimSpace(firstNonEmptyValue(config["collector_skip_cache"], config["collectorSkipCache"])))
	switch enabled {
	case "0", "false", "no", "off", "disabled":
		return 0, nil
	}
	value := strings.TrimSpace(firstNonEmptyValue(config["collector_skip_cache_ttl"], config["collectorSkipCacheTTL"]))
	if value == "" {
		return defaultCollectorSkipCacheTTL, nil
	}
	ttl, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid collector skip cache ttl %q: %w", value, err)
	}
	if ttl < 0 {
		return 0, fmt.Errorf("invalid collector skip cache ttl %q: must not be negative", value)
	}
	return ttl, nil
}

func assetProgressTasks(assets []provider.Asset) []string {
	tasks := make([]string, 0, len(assets))
	for _, asset := range assets {
		tasks = append(tasks, assetProgressTask(asset))
	}
	return tasks
}

func assetProgressTask(asset provider.Asset) string {
	label := firstNonEmptyValue(asset.Name, asset.ID, asset.Type, "asset")
	assetType := strings.TrimSpace(asset.Type)
	region := strings.TrimSpace(asset.Region)
	switch {
	case assetType != "" && region != "":
		return fmt.Sprintf("%s/%s@%s", assetType, label, region)
	case assetType != "":
		return fmt.Sprintf("%s/%s", assetType, label)
	case region != "":
		return fmt.Sprintf("%s@%s", label, region)
	default:
		return label
	}
}

func firstNonEmptyValue(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func assetKey(resourceType string, resourceID string) string {
	return strings.TrimSpace(resourceType) + "\x00" + strings.TrimSpace(resourceID)
}

func assetChanged(previous model.Asset, current model.Asset) bool {
	return previous.Provider != current.Provider ||
		previous.Region != current.Region ||
		previous.Name != current.Name ||
		string(previous.Properties) != string(current.Properties)
}

func selectedResourceTypeSet(config map[string]string) map[string]bool {
	selected := csvValues(config["resource_types"])
	if len(selected) == 0 {
		selected = csvValues(config["resources"])
	}
	if len(selected) == 0 {
		return nil
	}
	values := make(map[string]bool, len(selected))
	for _, item := range selected {
		normalized := normalizeAssetType(item)
		if normalized != "" {
			values[normalized] = true
		}
	}
	return values
}

func csvValues(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func resolveRulesDir(path string) (string, error) {
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return bundledRulesDir(), nil
	}
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate, nil
	}

	clean := filepath.Clean(candidate)
	if clean == "rules" {
		bundled := bundledRulesDir()
		if info, err := os.Stat(bundled); err == nil && info.IsDir() {
			return bundled, nil
		}
	}

	return candidate, nil
}

func bundledRulesDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "rules"
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "rules"))
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	text, _ := value.(string)
	return text
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
