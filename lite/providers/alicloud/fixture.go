package alicloud

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

type legacyMetadata struct {
	Platform     string `json:"platform"`
	ResourceType string `json:"resourceType"`
	AssetType    string `json:"asset_type"`
	Code         string `json:"code"`
	Legacy       struct {
		ResourceType string `json:"resourceType"`
	} `json:"legacy"`
}

func loadFixtureAssets(ctx context.Context, account liteprovider.Account, path string) ([]liteprovider.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	inputPath, err := resolveFixtureInputPath(path)
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read alicloud fixture %q: %w", inputPath, err)
	}

	value, err := decodeJSON(content)
	if err != nil {
		return nil, fmt.Errorf("decode alicloud fixture %q: %w", inputPath, err)
	}

	metadata, err := loadSiblingMetadata(inputPath)
	if err != nil {
		return nil, err
	}

	resourceType := firstNonEmpty(
		stringFromStringMap(account.Config, "resource_type", "resourceType", "asset_type", "assetType"),
		metadata.ResourceType,
		metadata.AssetType,
		metadata.Legacy.ResourceType,
	)

	fixture := fixtureContext{
		account:      account,
		metadata:     metadata,
		resourceType: resourceType,
	}
	return fixture.assetsFromValue(value)
}

func resolveFixtureInputPath(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat alicloud fixture %q: %w", path, err)
	}
	if info.IsDir() {
		return filepath.Join(path, "input.json"), nil
	}
	return path, nil
}

func loadSiblingMetadata(inputPath string) (legacyMetadata, error) {
	path := filepath.Join(filepath.Dir(inputPath), "metadata.json")
	content, err := os.ReadFile(path)
	if errorsIsNotExist(err) {
		return legacyMetadata{}, nil
	}
	if err != nil {
		return legacyMetadata{}, fmt.Errorf("read alicloud fixture metadata %q: %w", path, err)
	}

	var metadata legacyMetadata
	if err := json.Unmarshal(content, &metadata); err != nil {
		return legacyMetadata{}, fmt.Errorf("decode alicloud fixture metadata %q: %w", path, err)
	}
	return metadata, nil
}

func decodeJSON(content []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

type fixtureContext struct {
	account      liteprovider.Account
	metadata     legacyMetadata
	resourceType string
}

func (ctx fixtureContext) assetsFromValue(value any) ([]liteprovider.Asset, error) {
	switch typed := value.(type) {
	case []any:
		assets := make([]liteprovider.Asset, 0, len(typed))
		for _, item := range typed {
			assets = append(assets, ctx.assetFromRaw(item, nil))
		}
		return assets, nil
	case map[string]any:
		if assetsValue, ok := firstValue(typed, "assets", "resources"); ok {
			items, ok := assetsValue.([]any)
			if !ok {
				return nil, errorsNew("alicloud fixture assets must be an array")
			}

			envelopeType := firstNonEmpty(
				stringFromAnyKeys(typed, "resource_type", "resourceType", "asset_type", "assetType", "type"),
				ctx.resourceType,
			)
			assets := make([]liteprovider.Asset, 0, len(items))
			for _, item := range items {
				overrides, _ := item.(map[string]any)
				raw := rawInputFromMap(overrides, item)
				child := ctx
				child.resourceType = firstNonEmpty(
					stringFromAnyKeys(overrides, "resource_type", "resourceType", "asset_type", "assetType", "type"),
					envelopeType,
				)
				assets = append(assets, child.assetFromRaw(raw, overrides))
			}
			return assets, nil
		}

		if raw, ok := firstValue(typed, "input", "legacy_input", "properties"); ok && looksLikeFixtureEnvelope(typed) {
			child := ctx
			child.resourceType = firstNonEmpty(
				stringFromAnyKeys(typed, "resource_type", "resourceType", "asset_type", "assetType", "type"),
				ctx.resourceType,
			)
			return []liteprovider.Asset{child.assetFromRaw(raw, typed)}, nil
		}

		return []liteprovider.Asset{ctx.assetFromRaw(typed, nil)}, nil
	default:
		return []liteprovider.Asset{ctx.assetFromRaw(typed, nil)}, nil
	}
}

func (ctx fixtureContext) assetFromRaw(raw any, overrides map[string]any) liteprovider.Asset {
	properties := mapFromRaw(raw)

	resourceType := firstNonEmpty(
		stringFromAnyKeys(overrides, "resource_type", "resourceType", "asset_type", "assetType", "type"),
		ctx.resourceType,
		"unknown",
	)
	region := firstNonEmpty(
		stringFromAnyKeys(overrides, "region", "RegionId", "region_id"),
		inferRegion(properties),
		credentialValues(ctx.account).Region,
		"global",
	)
	rawID := firstNonEmpty(
		stringFromAnyKeys(overrides, "id", "resource_id", "resourceId", "ResourceId", "ResourceID"),
		inferResourceID(properties),
		stableFixtureID(properties),
	)
	name := firstNonEmpty(
		stringFromAnyKeys(overrides, "name", "resource_name", "resourceName", "ResourceName"),
		inferResourceName(properties),
		rawID,
	)

	return liteprovider.Asset{
		ID:         aliCloudAssetID(ctx.account.AccountID, region, resourceType, rawID),
		Provider:   ProviderName,
		AccountID:  ctx.account.AccountID,
		Type:       resourceType,
		Name:       name,
		Region:     region,
		Tags:       mergeTags(tagsFromAny(overrides["tags"]), inferTags(properties)),
		Properties: properties,
	}
}

func rawInputFromMap(values map[string]any, fallback any) any {
	if len(values) == 0 {
		return fallback
	}
	if raw, ok := firstValue(values, "input", "legacy_input", "properties"); ok {
		return raw
	}
	return fallback
}

func looksLikeFixtureEnvelope(values map[string]any) bool {
	_, hasType := firstValue(values, "resource_type", "resourceType", "asset_type", "assetType", "type")
	_, hasID := firstValue(values, "id", "resource_id", "resourceId", "ResourceId", "ResourceID")
	_, hasName := firstValue(values, "name", "resource_name", "resourceName", "ResourceName")
	return hasType || hasID || hasName
}

func mapFromRaw(raw any) map[string]any {
	if values, ok := raw.(map[string]any); ok {
		return cloneAnyMap(values)
	}
	return map[string]any{"value": raw}
}

func cloneAnyMap(values map[string]any) map[string]any {
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func inferResourceID(properties map[string]any) string {
	if value := firstNestedString(properties,
		[]string{"ResourceId"},
		[]string{"ResourceID"},
		[]string{"Instance", "InstanceId"},
		[]string{"BucketProperties", "Name"},
		[]string{"LoadBalancer", "LoadBalancerId"},
		[]string{"LoadBalancerAttribute", "LoadBalancerId"},
		[]string{"User", "UserId"},
		[]string{"UserDetail", "UserId"},
		[]string{"Role", "RoleId"},
		[]string{"DBInstance", "DBInstanceId"},
		[]string{"Cluster", "ClusterId"},
	); value != "" {
		return value
	}
	return firstRecursiveString(properties,
		"ResourceId",
		"ResourceID",
		"InstanceId",
		"BucketName",
		"Name",
		"LoadBalancerId",
		"UserId",
		"RoleId",
		"DBInstanceId",
		"ClusterId",
	)
}

func inferResourceName(properties map[string]any) string {
	if value := firstNestedString(properties,
		[]string{"ResourceName"},
		[]string{"Instance", "InstanceName"},
		[]string{"BucketProperties", "Name"},
		[]string{"LoadBalancer", "LoadBalancerName"},
		[]string{"LoadBalancerAttribute", "LoadBalancerName"},
		[]string{"User", "UserName"},
		[]string{"UserDetail", "UserName"},
		[]string{"Role", "RoleName"},
	); value != "" {
		return value
	}
	return firstRecursiveString(properties,
		"ResourceName",
		"InstanceName",
		"BucketName",
		"Name",
		"LoadBalancerName",
		"UserName",
		"RoleName",
		"DBInstanceDescription",
		"ClusterName",
	)
}

func inferRegion(properties map[string]any) string {
	if value := firstNestedString(properties,
		[]string{"RegionId"},
		[]string{"Region"},
		[]string{"BucketProperties", "Region"},
		[]string{"BucketProperties", "Location"},
		[]string{"Instance", "RegionId"},
		[]string{"LoadBalancer", "RegionId"},
		[]string{"LoadBalancerAttribute", "RegionId"},
	); value != "" {
		return value
	}
	return firstRecursiveString(properties, "RegionId", "Region", "Location")
}

func inferTags(properties map[string]any) map[string]string {
	if tags, ok := firstValue(properties, "Tags", "tags"); ok {
		return tagsFromAny(tags)
	}
	if nested, ok := firstRecursiveValue(properties, "Tags", "tags"); ok {
		return tagsFromAny(nested)
	}
	return nil
}

func firstNestedString(values map[string]any, paths ...[]string) string {
	for _, path := range paths {
		current := any(values)
		for _, segment := range path {
			currentMap, ok := current.(map[string]any)
			if !ok {
				current = nil
				break
			}
			current = currentMap[segment]
		}
		if value := stringFromAny(current); value != "" {
			return value
		}
	}
	return ""
}

func firstRecursiveString(value any, keys ...string) string {
	for _, key := range keys {
		if found, ok := recursiveString(value, key); ok {
			return found
		}
	}
	return ""
}

func recursiveString(value any, target string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if value := stringFromAny(typed[target]); value != "" {
			return value, true
		}
		keys := sortedKeys(typed)
		for _, key := range keys {
			if found, ok := recursiveString(typed[key], target); ok {
				return found, true
			}
		}
	case []any:
		for _, item := range typed {
			if found, ok := recursiveString(item, target); ok {
				return found, true
			}
		}
	}
	return "", false
}

func firstRecursiveValue(value any, keys ...string) (any, bool) {
	for _, key := range keys {
		if found, ok := recursiveValue(value, key); ok {
			return found, true
		}
	}
	return nil, false
}

func recursiveValue(value any, target string) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if value, ok := typed[target]; ok {
			return value, true
		}
		keys := sortedKeys(typed)
		for _, key := range keys {
			if found, ok := recursiveValue(typed[key], target); ok {
				return found, true
			}
		}
	case []any:
		for _, item := range typed {
			if found, ok := recursiveValue(item, target); ok {
				return found, true
			}
		}
	}
	return nil, false
}

func tagsFromAny(value any) map[string]string {
	switch typed := value.(type) {
	case map[string]string:
		return cloneStringMap(typed)
	case map[string]any:
		if nested, ok := firstValue(typed, "Tag", "tag"); ok {
			return tagsFromAny(nested)
		}

		tags := map[string]string{}
		for key, value := range typed {
			if stringValue := stringFromAny(value); stringValue != "" {
				tags[key] = stringValue
			}
		}
		return emptyToNil(tags)
	case []any:
		tags := map[string]string{}
		for _, item := range typed {
			values, ok := item.(map[string]any)
			if !ok {
				continue
			}
			key := firstNonEmpty(
				stringFromAnyKeys(values, "Key", "key", "TagKey", "tagKey"),
			)
			value := firstNonEmpty(
				stringFromAnyKeys(values, "Value", "value", "TagValue", "tagValue"),
			)
			if key != "" {
				tags[key] = value
			}
		}
		return emptyToNil(tags)
	default:
		return nil
	}
}

func mergeTags(left map[string]string, right map[string]string) map[string]string {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	merged := map[string]string{}
	for key, value := range right {
		merged[key] = value
	}
	for key, value := range left {
		merged[key] = value
	}
	return merged
}

func stableFixtureID(properties map[string]any) string {
	content, err := json.Marshal(properties)
	if err != nil {
		return "fixture"
	}
	sum := sha1.Sum(content)
	return hex.EncodeToString(sum[:])[:12]
}

func aliCloudAssetID(accountID string, region string, resourceType string, rawID string) string {
	return fmt.Sprintf("alicloud://%s/%s/%s/%s",
		pathSafe(accountID),
		pathSafe(region),
		pathSafe(resourceType),
		pathSafe(rawID),
	)
}

func pathSafe(value string) string {
	replacer := strings.NewReplacer("/", "_", " ", "_")
	return replacer.Replace(strings.TrimSpace(value))
}

func stringFromAnyKeys(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringFromAny(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}

func firstValue(values map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func emptyToNil(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	return values
}

func errorsNew(message string) error {
	return fmt.Errorf("%s", message)
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
