package alicloud

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	osssdk "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	osscredentials "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/antgroup/CloudRec/lite/internal/provider"
	coreschema "github.com/core-sdk/schema"
)

type OSSClient interface {
	ListBuckets(context.Context, *osssdk.ListBucketsRequest, ...func(*osssdk.Options)) (*osssdk.ListBucketsResult, error)
	GetBucketInfo(context.Context, *osssdk.GetBucketInfoRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketInfoResult, error)
	GetBucketLogging(context.Context, *osssdk.GetBucketLoggingRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketLoggingResult, error)
	GetBucketPolicy(context.Context, *osssdk.GetBucketPolicyRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketPolicyResult, error)
	GetBucketPolicyStatus(context.Context, *osssdk.GetBucketPolicyStatusRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketPolicyStatusResult, error)
	GetBucketEncryption(context.Context, *osssdk.GetBucketEncryptionRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketEncryptionResult, error)
	GetBucketVersioning(context.Context, *osssdk.GetBucketVersioningRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketVersioningResult, error)
	GetBucketReferer(context.Context, *osssdk.GetBucketRefererRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketRefererResult, error)
	GetBucketCors(context.Context, *osssdk.GetBucketCorsRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketCorsResult, error)
	ListBucketInventory(context.Context, *osssdk.ListBucketInventoryRequest, ...func(*osssdk.Options)) (*osssdk.ListBucketInventoryResult, error)
}

type OSSClientFactory func(region string, credentials Credentials, timeout time.Duration) OSSClient

type OSSAdapter struct {
	clientFactory OSSClientFactory
}

var errEmptyOSSBucketName = errors.New("oss bucket name is empty")

type OSSAdapterOption func(*OSSAdapter)

func NewOSSAdapter(options ...OSSAdapterOption) *OSSAdapter {
	adapter := &OSSAdapter{
		clientFactory: newOSSClient,
	}
	for _, option := range options {
		option(adapter)
	}
	return adapter
}

func WithOSSClientFactory(factory OSSClientFactory) OSSAdapterOption {
	return func(adapter *OSSAdapter) {
		if factory != nil {
			adapter.clientFactory = factory
		}
	}
}

func (a *OSSAdapter) Spec() ResourceSpec {
	for _, spec := range AllResourceSpecs() {
		if normalizeResourceType(spec.Type) == "oss" {
			return spec
		}
	}
	return ResourceSpec{Type: "OSS", Group: "STORE", Dimension: DimensionGlobal}
}

func (a *OSSAdapter) Collect(ctx context.Context, request AdapterRequest) ([]provider.Asset, error) {
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	collectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	listRegion := ossListRegion(request)
	listClient := a.clientFactory(listRegion, request.Credentials, timeout)
	buckets, err := listOSSBuckets(collectCtx, listClient)
	if err != nil {
		return nil, err
	}

	if filters := ossBucketRegionFilter(request.Account); len(filters) > 0 {
		buckets = filterOSSBucketsByRegion(buckets, filters)
	}

	clients := map[string]OSSClient{listRegion: listClient}
	var assets []provider.Asset
	var failures []provider.CollectionFailure
	for _, bucket := range buckets {
		region := firstNonEmpty(valueString(bucket.Region), listRegion)
		client := clients[region]
		if client == nil {
			client = a.clientFactory(region, request.Credentials, timeout)
			clients[region] = client
		}

		asset, err := a.collectBucket(collectCtx, request.Account, client, bucket, region)
		if err != nil {
			failures = append(failures, resourceFailure("OSS", region, err))
			continue
		}
		assets = append(assets, asset)
	}

	return assets, partialCollectionError(assets, failures)
}

func newOSSClient(region string, credentials Credentials, timeout time.Duration) OSSClient {
	provider := osscredentials.NewStaticCredentialsProvider(
		credentials.AccessKeyID,
		credentials.AccessKeySecret,
		credentials.SecurityToken,
	)
	cfg := osssdk.LoadDefaultConfig().
		WithCredentialsProvider(provider).
		WithRegion(region).
		WithRetryMaxAttempts(2).
		WithConnectTimeout(timeout).
		WithReadWriteTimeout(timeout)
	return osssdk.NewClient(cfg)
}

func listOSSBuckets(ctx context.Context, client OSSClient) ([]osssdk.BucketProperties, error) {
	var (
		buckets []osssdk.BucketProperties
		marker  *string
	)
	for {
		page, err := client.ListBuckets(ctx, &osssdk.ListBucketsRequest{
			MaxKeys: 1000,
			Marker:  marker,
		})
		if err != nil {
			return buckets, err
		}
		if page == nil {
			return buckets, nil
		}
		buckets = append(buckets, page.Buckets...)
		if !page.IsTruncated {
			return buckets, nil
		}
		marker = page.NextMarker
		if marker == nil || strings.TrimSpace(*marker) == "" {
			return buckets, nil
		}
	}
}

func (a *OSSAdapter) collectBucket(ctx context.Context, account provider.Account, client OSSClient, bucket osssdk.BucketProperties, region string) (provider.Asset, error) {
	name := bucket.Name
	if name == nil || strings.TrimSpace(*name) == "" {
		return provider.Asset{}, errEmptyOSSBucketName
	}

	detail := ossBucketDetail{
		BucketProperties:       bucket,
		BucketInfo:             getNativeBucketInfo(ctx, client, name),
		LoggingEnabled:         getNativeBucketLogging(ctx, client, name),
		BucketPolicy:           getNativeBucketPolicy(ctx, client, name),
		BucketPolicyStatus:     getNativeBucketPolicyStatus(ctx, client, name),
		SSEDefaultRule:         getNativeBucketEncryption(ctx, client, name),
		VersioningConfig:       getNativeBucketVersioning(ctx, client, name),
		RefererConfiguration:   getNativeBucketReferer(ctx, client, name),
		CORSConfiguration:      getNativeBucketCORS(ctx, client, name),
		InventoryConfiguration: getNativeBucketInventory(ctx, client, name),
	}

	return assetFromLegacyData(account, ossLegacyResource(), region, detail)
}

type ossBucketDetail struct {
	BucketProperties       osssdk.BucketProperties
	BucketInfo             *osssdk.BucketInfo
	LoggingEnabled         *osssdk.LoggingEnabled
	BucketPolicy           any
	BucketPolicyStatus     *osssdk.PolicyStatus
	SSEDefaultRule         *osssdk.ApplyServerSideEncryptionByDefault
	VersioningConfig       any
	RefererConfiguration   any
	CORSConfiguration      any
	InventoryConfiguration []map[string]any
}

func ossLegacyResource() coreschema.Resource {
	return coreschema.Resource{
		ResourceType: "OSS",
		RowField: coreschema.RowField{
			ResourceId:   "$.BucketProperties.Name",
			ResourceName: "$.BucketProperties.Name",
		},
		Dimension: coreschema.Global,
	}
}

func getNativeBucketInfo(ctx context.Context, client OSSClient, name *string) *osssdk.BucketInfo {
	result, err := client.GetBucketInfo(ctx, &osssdk.GetBucketInfoRequest{Bucket: name})
	if err != nil || result == nil {
		return nil
	}
	return &result.BucketInfo
}

func getNativeBucketLogging(ctx context.Context, client OSSClient, name *string) *osssdk.LoggingEnabled {
	result, err := client.GetBucketLogging(ctx, &osssdk.GetBucketLoggingRequest{Bucket: name})
	if err != nil || result == nil || result.BucketLoggingStatus == nil {
		return nil
	}
	return result.BucketLoggingStatus.LoggingEnabled
}

func getNativeBucketPolicy(ctx context.Context, client OSSClient, name *string) any {
	result, err := client.GetBucketPolicy(ctx, &osssdk.GetBucketPolicyRequest{Bucket: name})
	if err != nil || result == nil || strings.TrimSpace(result.Body) == "" {
		return nil
	}
	var policy any
	if err := json.Unmarshal([]byte(result.Body), &policy); err != nil {
		return nil
	}
	return policy
}

func getNativeBucketPolicyStatus(ctx context.Context, client OSSClient, name *string) *osssdk.PolicyStatus {
	result, err := client.GetBucketPolicyStatus(ctx, &osssdk.GetBucketPolicyStatusRequest{Bucket: name})
	if err != nil || result == nil {
		return nil
	}
	return result.PolicyStatus
}

func getNativeBucketEncryption(ctx context.Context, client OSSClient, name *string) *osssdk.ApplyServerSideEncryptionByDefault {
	result, err := client.GetBucketEncryption(ctx, &osssdk.GetBucketEncryptionRequest{Bucket: name})
	if err != nil || result == nil || result.ServerSideEncryptionRule == nil {
		return nil
	}
	return result.ServerSideEncryptionRule.ApplyServerSideEncryptionByDefault
}

func getNativeBucketVersioning(ctx context.Context, client OSSClient, name *string) any {
	result, err := client.GetBucketVersioning(ctx, &osssdk.GetBucketVersioningRequest{Bucket: name})
	if err != nil || result == nil || result.VersionStatus == nil {
		return nil
	}
	return map[string]any{"Status": valueString(result.VersionStatus)}
}

func getNativeBucketReferer(ctx context.Context, client OSSClient, name *string) any {
	result, err := client.GetBucketReferer(ctx, &osssdk.GetBucketRefererRequest{Bucket: name})
	if err != nil || result == nil || result.RefererConfiguration == nil {
		return nil
	}
	configuration := mapFromJSON(result.RefererConfiguration)
	if result.RefererConfiguration.RefererList != nil {
		configuration["RefererList"] = append([]string(nil), result.RefererConfiguration.RefererList.Referers...)
	}
	if result.RefererConfiguration.RefererBlacklist != nil {
		configuration["RefererBlacklist"] = append([]string(nil), result.RefererConfiguration.RefererBlacklist.Referers...)
	}
	return configuration
}

func getNativeBucketCORS(ctx context.Context, client OSSClient, name *string) any {
	result, err := client.GetBucketCors(ctx, &osssdk.GetBucketCorsRequest{Bucket: name})
	if err != nil || result == nil || result.CORSConfiguration == nil {
		return nil
	}
	rules := make([]map[string]any, 0, len(result.CORSConfiguration.CORSRules))
	for _, rule := range result.CORSConfiguration.CORSRules {
		values := mapFromJSON(rule)
		values["AllowedOrigin"] = append([]string(nil), rule.AllowedOrigins...)
		values["AllowedMethod"] = append([]string(nil), rule.AllowedMethods...)
		values["AllowedHeader"] = append([]string(nil), rule.AllowedHeaders...)
		values["ExposeHeader"] = append([]string(nil), rule.ExposeHeaders...)
		rules = append(rules, values)
	}
	return map[string]any{
		"CORSRules":    rules,
		"ResponseVary": valueBool(result.CORSConfiguration.ResponseVary),
	}
}

func getNativeBucketInventory(ctx context.Context, client OSSClient, name *string) []map[string]any {
	var (
		configurations []map[string]any
		token          *string
	)
	for {
		result, err := client.ListBucketInventory(ctx, &osssdk.ListBucketInventoryRequest{
			Bucket:            name,
			ContinuationToken: token,
		})
		if err != nil || result == nil || result.ListInventoryConfigurationsResult == nil {
			return configurations
		}
		for _, configuration := range result.ListInventoryConfigurationsResult.InventoryConfigurations {
			configurations = append(configurations, normalizeInventoryConfiguration(configuration))
		}
		if result.ListInventoryConfigurationsResult.IsTruncated == nil || !*result.ListInventoryConfigurationsResult.IsTruncated {
			return configurations
		}
		token = result.ListInventoryConfigurationsResult.NextContinuationToken
		if token == nil || strings.TrimSpace(*token) == "" {
			return configurations
		}
	}
}

func normalizeInventoryConfiguration(configuration osssdk.InventoryConfiguration) map[string]any {
	values := mapFromJSON(configuration)
	if configuration.Destination != nil && configuration.Destination.OSSBucketDestination != nil {
		values["OSSBucketDestination"] = mapFromJSON(configuration.Destination.OSSBucketDestination)
	}
	if configuration.Filter != nil && configuration.Filter.Prefix != nil {
		values["Prefix"] = valueString(configuration.Filter.Prefix)
	}
	return values
}

func mapFromJSON(value any) map[string]any {
	_, properties, err := legacyProperties(value)
	if err != nil {
		return map[string]any{}
	}
	return properties
}

func ossListRegion(request AdapterRequest) string {
	if value := firstNonEmpty(request.Credentials.Region, firstNonGlobal(request.Regions)); value != "" {
		return value
	}
	return "cn-hangzhou"
}

func ossBucketRegionFilter(account provider.Account) map[string]struct{} {
	regions := explicitRegions(account)
	if len(regions) == 0 {
		return nil
	}
	filter := map[string]struct{}{}
	for _, region := range regions {
		region = strings.TrimSpace(region)
		if region == "" || region == "global" {
			continue
		}
		filter[region] = struct{}{}
	}
	return filter
}

func filterOSSBucketsByRegion(buckets []osssdk.BucketProperties, filters map[string]struct{}) []osssdk.BucketProperties {
	if len(filters) == 0 {
		return buckets
	}
	filtered := make([]osssdk.BucketProperties, 0, len(buckets))
	for _, bucket := range buckets {
		if _, ok := filters[valueString(bucket.Region)]; ok {
			filtered = append(filtered, bucket)
		}
	}
	return filtered
}

func firstNonGlobal(values []string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && value != "global" {
			return value
		}
	}
	return ""
}

func valueString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func valueBool(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}
