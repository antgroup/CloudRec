package rule

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrYAMLMetadataUnsupported = errors.New("yaml rule metadata is not supported yet")

type LoadDirOptions struct {
	IncludeDisabled bool
}

func LoadDir(root string) ([]RulePack, error) {
	return LoadDirWithOptions(root, LoadDirOptions{})
}

func LoadDirWithOptions(root string, options LoadDirOptions) ([]RulePack, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat rules directory %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules path %q is not a directory", root)
	}

	packDirs := map[string]struct{}{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		if path != root && shouldSkipDir(entry.Name()) {
			return filepath.SkipDir
		}
		if _, err := os.Stat(filepath.Join(path, "policy.rego")); err == nil {
			packDirs[path] = struct{}{}
			if path != root {
				return filepath.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk rules directory %q: %w", root, err)
	}

	dirs := make([]string, 0, len(packDirs))
	for dir := range packDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	packs := make([]RulePack, 0, len(dirs))
	for _, dir := range dirs {
		pack, err := loadPack(dir, root)
		if err != nil {
			return nil, err
		}
		if pack.Metadata.Disabled && !options.IncludeDisabled {
			continue
		}
		packs = append(packs, pack)
	}
	return packs, nil
}

func LoadPack(dir string) (RulePack, error) {
	return loadPack(dir, "")
}

func loadPack(dir string, rulesRoot string) (RulePack, error) {
	metadataPath, err := findMetadataPath(dir)
	if err != nil {
		return RulePack{}, err
	}

	metadata, err := loadJSONMetadata(metadataPath)
	if err != nil {
		return RulePack{}, err
	}
	if err := metadata.Validate(); err != nil {
		return RulePack{}, fmt.Errorf("validate %s: %w", metadataPath, err)
	}

	policyPath := filepath.Join(dir, "policy.rego")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return RulePack{}, fmt.Errorf("read policy %q: %w", policyPath, err)
	}
	if strings.TrimSpace(string(policy)) == "" {
		return RulePack{}, fmt.Errorf("policy %q is empty", policyPath)
	}

	pack := RulePack{
		Dir:          dir,
		MetadataPath: metadataPath,
		PolicyPath:   policyPath,
		Metadata:     metadata,
		Policy:       string(policy),
	}

	if path := filepath.Join(dir, "remediation.md"); fileExists(path) {
		content, err := os.ReadFile(path)
		if err != nil {
			return RulePack{}, fmt.Errorf("read remediation %q: %w", path, err)
		}
		pack.RemediationPath = path
		pack.Remediation = string(content)
	}

	if path := filepath.Join(dir, "examples.json"); fileExists(path) {
		examples, err := loadExamples(path)
		if err != nil {
			return RulePack{}, err
		}
		pack.ExamplesPath = path
		pack.Examples = examples
	}

	if path := filepath.Join(dir, "input.json"); fileExists(path) {
		content, err := os.ReadFile(path)
		if err != nil {
			return RulePack{}, fmt.Errorf("read input example %q: %w", path, err)
		}
		pack.InputPath = path
		if len(pack.Examples) == 0 {
			pack.Examples = []RuleExample{{
				Name:         "input.json",
				Input:        json.RawMessage(content),
				WantFindings: -1,
			}}
		}
	}

	if path := filepath.Join(dir, "relation.json"); fileExists(path) {
		refs, err := loadRelationRefs(path)
		if err != nil {
			return RulePack{}, err
		}
		pack.RelationPath = path
		if len(refs) > 0 {
			data, dataPaths, missingDataRefs, err := loadRelationData(dir, rulesRoot, refs)
			if err != nil {
				return RulePack{}, err
			}
			pack.Data = data
			pack.DataPaths = dataPaths
			pack.MissingDataRefs = missingDataRefs
		}
	}

	return pack, nil
}

func findMetadataPath(dir string) (string, error) {
	jsonPath := filepath.Join(dir, "metadata.json")
	if fileExists(jsonPath) {
		return jsonPath, nil
	}

	for _, name := range []string{"metadata.yaml", "metadata.yml"} {
		path := filepath.Join(dir, name)
		if fileExists(path) {
			// TODO: add YAML decoding once Lite settles on whether to take a YAML dependency.
			return "", fmt.Errorf("%w: %s", ErrYAMLMetadataUnsupported, path)
		}
	}

	return "", fmt.Errorf("rule pack %q missing metadata.json", dir)
}

func loadJSONMetadata(path string) (RuleMetadata, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return RuleMetadata{}, fmt.Errorf("read metadata %q: %w", path, err)
	}

	var metadata RuleMetadata
	if err := json.Unmarshal(content, &metadata); err != nil {
		return RuleMetadata{}, fmt.Errorf("decode metadata %q: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return RuleMetadata{}, fmt.Errorf("decode metadata aliases %q: %w", path, err)
	}

	return normalizeMetadata(metadata, raw), nil
}

func loadExamples(path string) ([]RuleExample, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read examples %q: %w", path, err)
	}

	var examples []RuleExample
	if err := json.Unmarshal(content, &examples); err == nil {
		return examples, nil
	}

	var envelope struct {
		Examples []RuleExample `json:"examples"`
	}
	if err := json.Unmarshal(content, &envelope); err != nil {
		return nil, fmt.Errorf("decode examples %q: %w", path, err)
	}
	return envelope.Examples, nil
}

func normalizeMetadata(metadata RuleMetadata, raw map[string]json.RawMessage) RuleMetadata {
	legacy := rawObject(raw, "legacy")
	if metadata.ID == "" {
		metadata.ID = firstNonEmpty(rawString(raw, "code"), rawString(legacy, "code"))
	}
	if metadata.Severity == "" {
		metadata.Severity = Severity(firstNonEmpty(rawString(raw, "level"), rawString(legacy, "level")))
	}
	if metadata.Provider == "" {
		metadata.Provider = firstNonEmpty(rawString(raw, "platform"), rawString(legacy, "platform"))
	}
	if metadata.AssetType == "" {
		metadata.AssetType = firstNonEmpty(rawString(raw, "resourceType"), rawString(legacy, "resourceType"))
	}
	if metadata.Service == "" {
		metadata.Service = metadata.AssetType
	}
	if len(metadata.Categories) == 0 {
		metadata.Categories = rawStringSlice(raw, "categoryList")
		if len(metadata.Categories) == 0 {
			metadata.Categories = rawStringSlice(legacy, "categoryList")
		}
	}
	if metadata.Context == "" {
		metadata.Context = firstNonEmpty(rawString(raw, "context"), rawString(legacy, "context"))
	}
	if metadata.Advice == "" {
		metadata.Advice = firstNonEmpty(rawString(raw, "advice"), rawString(legacy, "advice"))
	}
	if metadata.Link == "" {
		metadata.Link = firstNonEmpty(rawString(raw, "link"), rawString(legacy, "link"))
	}
	if len(metadata.LinkedData) == 0 {
		metadata.LinkedData = rawLinkedDataList(raw, "linkedDataList")
		if len(metadata.LinkedData) == 0 {
			metadata.LinkedData = rawLinkedDataList(legacy, "linkedDataList")
		}
	}

	metadata.ID = strings.TrimSpace(metadata.ID)
	metadata.Name = strings.TrimSpace(metadata.Name)
	metadata.Description = strings.TrimSpace(metadata.Description)
	metadata.Provider = strings.TrimSpace(metadata.Provider)
	metadata.Service = strings.TrimSpace(metadata.Service)
	metadata.AssetType = strings.TrimSpace(metadata.AssetType)
	metadata.Context = strings.TrimSpace(metadata.Context)
	metadata.Advice = strings.TrimSpace(metadata.Advice)
	metadata.Link = strings.TrimSpace(metadata.Link)
	metadata.LinkedData = cleanLinkedDataSpecs(metadata.LinkedData)
	metadata.Severity = normalizeSeverity(metadata.Severity)
	return metadata
}

func rawObject(raw map[string]json.RawMessage, field string) map[string]json.RawMessage {
	value, ok := raw[field]
	if !ok || string(value) == "null" {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil {
		return nil
	}
	return object
}

func normalizeSeverity(severity Severity) Severity {
	value := strings.ToLower(strings.TrimSpace(string(severity)))
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")

	switch value {
	case "critical", "crit", "严重", "严重风险":
		return SeverityCritical
	case "high", "高", "高危", "高风险":
		return SeverityHigh
	case "medium", "middle", "moderate", "中", "中危", "中风险":
		return SeverityMedium
	case "low", "低", "低危", "低风险":
		return SeverityLow
	case "info", "informational", "none", "提示":
		return SeverityInfo
	default:
		return Severity(value)
	}
}

func rawString(raw map[string]json.RawMessage, field string) string {
	value, ok := raw[field]
	if !ok || string(value) == "null" {
		return ""
	}

	var decoded string
	if err := json.Unmarshal(value, &decoded); err == nil {
		return strings.TrimSpace(decoded)
	}
	return ""
}

func rawStringSlice(raw map[string]json.RawMessage, field string) []string {
	value, ok := raw[field]
	if !ok || string(value) == "null" {
		return nil
	}

	var values []string
	if err := json.Unmarshal(value, &values); err == nil {
		return cleanStrings(values)
	}

	var single string
	if err := json.Unmarshal(value, &single); err == nil && strings.TrimSpace(single) != "" {
		return []string{strings.TrimSpace(single)}
	}
	return nil
}

func rawLinkedDataList(raw map[string]json.RawMessage, field string) []LinkedDataSpec {
	value, ok := raw[field]
	if !ok || string(value) == "null" {
		return nil
	}

	var specs []LinkedDataSpec
	if err := json.Unmarshal(value, &specs); err == nil {
		return cleanLinkedDataSpecs(specs)
	}

	var encoded string
	if err := json.Unmarshal(value, &encoded); err != nil || strings.TrimSpace(encoded) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(encoded), &specs); err != nil {
		return nil
	}
	return cleanLinkedDataSpecs(specs)
}

func cleanLinkedDataSpecs(specs []LinkedDataSpec) []LinkedDataSpec {
	cleaned := make([]LinkedDataSpec, 0, len(specs))
	for _, spec := range specs {
		spec.AssociativeMode = strings.TrimSpace(spec.AssociativeMode)
		spec.LinkedKey1 = strings.TrimSpace(spec.LinkedKey1)
		spec.LinkedKey2 = strings.TrimSpace(spec.LinkedKey2)
		spec.NewKeyName = strings.TrimSpace(spec.NewKeyName)
		spec.ResourceType = cleanStrings(spec.ResourceType)
		if spec.LinkedKey1 == "" || spec.LinkedKey2 == "" || spec.NewKeyName == "" || len(spec.ResourceType) == 0 {
			continue
		}
		cleaned = append(cleaned, spec)
	}
	return cleaned
}

func loadRelationRefs(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read relation %q: %w", path, err)
	}
	if strings.TrimSpace(string(content)) == "" {
		return nil, nil
	}

	var refs []string
	if err := json.Unmarshal(content, &refs); err == nil {
		return cleanStrings(refs), nil
	}

	var rawItems []map[string]any
	if err := json.Unmarshal(content, &rawItems); err == nil {
		for _, item := range rawItems {
			for _, key := range []string{"path", "file", "name", "data"} {
				if value, ok := item[key].(string); ok {
					refs = append(refs, value)
					break
				}
			}
		}
		return cleanStrings(refs), nil
	}

	var envelope struct {
		Data      []string `json:"data"`
		DataRefs  []string `json:"dataRefs"`
		Relations []string `json:"relations"`
	}
	if err := json.Unmarshal(content, &envelope); err != nil {
		return nil, fmt.Errorf("decode relation %q: %w", path, err)
	}
	refs = append(refs, envelope.Data...)
	refs = append(refs, envelope.DataRefs...)
	refs = append(refs, envelope.Relations...)
	return cleanStrings(refs), nil
}

func loadRelationData(packDir string, rulesRoot string, refs []string) (map[string]any, []string, []string, error) {
	data := map[string]any{}
	dataPaths := make([]string, 0, len(refs))
	missingRefs := []string{}

	for _, ref := range refs {
		path, err := resolveDataRef(packDir, rulesRoot, ref)
		if err != nil {
			missingRefs = append(missingRefs, ref)
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read relation data %q: %w", path, err)
		}

		var value any
		if err := json.Unmarshal(content, &value); err != nil {
			return nil, nil, nil, fmt.Errorf("decode relation data %q: %w", path, err)
		}

		mergeRuleData(data, dataKeyForRef(ref, path), value)
		dataPaths = append(dataPaths, path)
	}

	sort.Strings(dataPaths)
	sort.Strings(missingRefs)
	if len(data) == 0 {
		data = nil
	}
	return data, dataPaths, missingRefs, nil
}

func resolveDataRef(packDir string, rulesRoot string, ref string) (string, error) {
	for _, path := range candidateDataPaths(packDir, rulesRoot, ref) {
		if fileExists(path) {
			return path, nil
		}
	}
	return "", fmt.Errorf("resolve relation data %q for rule pack %q", ref, packDir)
}

func candidateDataPaths(packDir string, rulesRoot string, ref string) []string {
	ref = filepath.Clean(strings.TrimSpace(ref))
	if ref == "." || ref == "" {
		return nil
	}

	refs := []string{ref}
	if filepath.Ext(ref) == "" {
		refs = append(refs, ref+".json")
	}

	var candidates []string
	addCandidate := func(path string) {
		path = filepath.Clean(path)
		for _, candidate := range candidates {
			if candidate == path {
				return
			}
		}
		candidates = append(candidates, path)
	}

	if filepath.IsAbs(ref) {
		for _, value := range refs {
			addCandidate(value)
		}
		return candidates
	}

	roots := []string{packDir}
	if rulesRoot != "" {
		roots = append(roots, rulesRoot)
	}
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}

	for _, root := range roots {
		if root == "" {
			continue
		}
		for _, value := range refs {
			addCandidate(filepath.Join(root, value))
			addCandidate(filepath.Join(root, "data", value))
		}
	}

	for ancestor := packDir; ancestor != "." && ancestor != string(filepath.Separator); ancestor = filepath.Dir(ancestor) {
		for _, value := range refs {
			addCandidate(filepath.Join(ancestor, "data", value))
		}
		next := filepath.Dir(ancestor)
		if next == ancestor {
			break
		}
	}

	return candidates
}

func dataKeyForRef(ref string, path string) string {
	key := strings.TrimSuffix(filepath.Base(ref), filepath.Ext(ref))
	if key == "." || key == "" {
		key = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return key
}

func mergeRuleData(target map[string]any, key string, value any) {
	if object, ok := value.(map[string]any); ok {
		for nestedKey, nestedValue := range object {
			target[nestedKey] = nestedValue
		}
		return
	}
	target[key] = value
}

func cleanStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func shouldSkipDir(name string) bool {
	return strings.HasPrefix(name, ".") || name == "testdata"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
