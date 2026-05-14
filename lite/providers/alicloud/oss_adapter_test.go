package alicloud

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	osssdk "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

func TestOSSAdapterCollectsRuleCompatibleAsset(t *testing.T) {
	client := &fakeOSSClient{
		buckets: []osssdk.BucketProperties{{
			Name:             osssdk.Ptr("bucket-demo"),
			Region:           osssdk.Ptr("cn-hangzhou"),
			ExtranetEndpoint: osssdk.Ptr("oss-cn-hangzhou.aliyuncs.com"),
		}},
		bucketInfo: &osssdk.BucketInfo{
			Name:              osssdk.Ptr("bucket-demo"),
			ACL:               osssdk.Ptr("public-read"),
			BlockPublicAccess: osssdk.Ptr(false),
			SseRule: osssdk.SSERule{
				SSEAlgorithm: osssdk.Ptr("KMS"),
			},
		},
		logging: &osssdk.LoggingEnabled{
			TargetBucket: osssdk.Ptr("bucket-log"),
			TargetPrefix: osssdk.Ptr("logs/"),
		},
		policyBody: `{"Statement":[{"Effect":"Allow","Principal":["*"]}]}`,
		policyStatus: &osssdk.PolicyStatus{
			IsPublic: osssdk.Ptr(true),
		},
		encryption: &osssdk.ApplyServerSideEncryptionByDefault{
			SSEAlgorithm: osssdk.Ptr("KMS"),
		},
		versioning: osssdk.Ptr("Enabled"),
		referer: &osssdk.RefererConfiguration{
			RefererList: &osssdk.RefererList{Referers: []string{"*"}},
		},
		cors: &osssdk.CORSConfiguration{
			CORSRules: []osssdk.CORSRule{{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET"},
			}},
		},
		inventory: []osssdk.InventoryConfiguration{{
			Id: osssdk.Ptr("inventory-1"),
			Destination: &osssdk.InventoryDestination{
				OSSBucketDestination: &osssdk.InventoryOSSBucketDestination{
					AccountId: osssdk.Ptr("123456789"),
					Bucket:    osssdk.Ptr("acs:oss:::dest-bucket"),
					Prefix:    osssdk.Ptr("exports/"),
				},
			},
			Filter: &osssdk.InventoryFilter{
				Prefix: osssdk.Ptr("source/"),
			},
		}},
	}

	adapter := NewOSSAdapter(WithOSSClientFactory(func(string, Credentials, time.Duration) OSSClient {
		return client
	}))
	assets, err := adapter.Collect(context.Background(), AdapterRequest{
		Account: liteprovider.Account{
			AccountID: "123456789",
		},
		Credentials: Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"},
		Regions:     []string{"cn-hangzhou"},
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("len(assets) = %d, want 1", len(assets))
	}

	asset := assets[0]
	if asset.ID != "alicloud://123456789/cn-hangzhou/OSS/bucket-demo" {
		t.Fatalf("asset ID = %q, want stable OSS asset ID", asset.ID)
	}
	if asset.Type != "OSS" || asset.Region != "cn-hangzhou" || asset.Name != "bucket-demo" {
		t.Fatalf("asset = %#v, want OSS bucket-demo in cn-hangzhou", asset)
	}

	bucketInfo := mapValue(t, asset.Properties, "BucketInfo")
	if bucketInfo["ACL"] != "public-read" {
		t.Fatalf("BucketInfo.ACL = %#v, want public-read", bucketInfo["ACL"])
	}
	if sseRule := mapValue(t, bucketInfo, "SseRule"); sseRule["SSEAlgorithm"] != "KMS" {
		t.Fatalf("BucketInfo.SseRule = %#v, want SSEAlgorithm=KMS", sseRule)
	}
	if versioning := mapValue(t, asset.Properties, "VersioningConfig"); versioning["Status"] != "Enabled" {
		t.Fatalf("VersioningConfig = %#v, want Status=Enabled", versioning)
	}
	if policyStatus := mapValue(t, asset.Properties, "BucketPolicyStatus"); policyStatus["IsPublic"] != true {
		t.Fatalf("BucketPolicyStatus = %#v, want IsPublic=true", policyStatus)
	}
	if referer := mapValue(t, asset.Properties, "RefererConfiguration"); !containsAnyString(sliceValue(t, referer, "RefererList"), "*") {
		t.Fatalf("RefererConfiguration = %#v, want RefererList containing *", referer)
	}
	corsRules := sliceValue(t, mapValue(t, asset.Properties, "CORSConfiguration"), "CORSRules")
	if len(corsRules) != 1 || !containsAnyString(sliceValue(t, corsRules[0].(map[string]any), "AllowedOrigin"), "*") {
		t.Fatalf("CORSRules = %#v, want AllowedOrigin containing *", corsRules)
	}
	inventory := sliceValue(t, asset.Properties, "InventoryConfiguration")
	if len(inventory) != 1 {
		t.Fatalf("InventoryConfiguration = %#v, want one item", inventory)
	}
	inventoryItem := inventory[0].(map[string]any)
	if destination := mapValue(t, inventoryItem, "OSSBucketDestination"); destination["Bucket"] != "acs:oss:::dest-bucket" {
		t.Fatalf("OSSBucketDestination = %#v, want flattened destination", destination)
	}
	if inventoryItem["Prefix"] != "source/" {
		t.Fatalf("InventoryConfiguration.Prefix = %#v, want source/", inventoryItem["Prefix"])
	}
}

func TestOSSAdapterFiltersExplicitRegions(t *testing.T) {
	client := &fakeOSSClient{
		buckets: []osssdk.BucketProperties{
			{Name: osssdk.Ptr("bucket-hz"), Region: osssdk.Ptr("cn-hangzhou")},
			{Name: osssdk.Ptr("bucket-bj"), Region: osssdk.Ptr("cn-beijing")},
		},
	}
	adapter := NewOSSAdapter(WithOSSClientFactory(func(string, Credentials, time.Duration) OSSClient {
		return client
	}))

	assets, err := adapter.Collect(context.Background(), AdapterRequest{
		Account: liteprovider.Account{
			AccountID: "123456789",
			Config: map[string]string{
				"regions": "cn-hangzhou",
			},
		},
		Credentials: Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"},
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(assets) != 1 || assets[0].Name != "bucket-hz" {
		t.Fatalf("assets = %#v, want only cn-hangzhou bucket", assets)
	}
}

func TestHybridCollectorRoutesNativeAndLegacyResources(t *testing.T) {
	native := NewRegistryCollector(WithResourceAdapter(fakeResourceAdapter{
		spec:   ResourceSpec{Type: "OSS", Group: "STORE", Dimension: DimensionGlobal},
		assets: []liteprovider.Asset{{ID: "oss-1", Type: "OSS"}},
	}))
	legacy := &recordingCollector{
		assets: []liteprovider.Asset{{ID: "ecs-1", Type: "ECS"}},
	}
	collector := NewHybridCollector(native, legacy)

	assets, err := collector.Collect(context.Background(), liteprovider.Account{
		AccountID: "123456789",
		Config: map[string]string{
			"resource_types": "OSS,ECS",
		},
	}, Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets = %#v, want native and legacy assets", assets)
	}
	if legacy.resourceTypes != "ECS" {
		t.Fatalf("legacy resource_types = %q, want ECS", legacy.resourceTypes)
	}
}

type fakeOSSClient struct {
	buckets      []osssdk.BucketProperties
	bucketInfo   *osssdk.BucketInfo
	logging      *osssdk.LoggingEnabled
	policyBody   string
	policyStatus *osssdk.PolicyStatus
	encryption   *osssdk.ApplyServerSideEncryptionByDefault
	versioning   *string
	referer      *osssdk.RefererConfiguration
	cors         *osssdk.CORSConfiguration
	inventory    []osssdk.InventoryConfiguration
	err          error
}

func (client *fakeOSSClient) ListBuckets(context.Context, *osssdk.ListBucketsRequest, ...func(*osssdk.Options)) (*osssdk.ListBucketsResult, error) {
	if client.err != nil {
		return nil, client.err
	}
	return &osssdk.ListBucketsResult{Buckets: client.buckets}, nil
}

func (client *fakeOSSClient) GetBucketInfo(context.Context, *osssdk.GetBucketInfoRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketInfoResult, error) {
	if client.bucketInfo == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketInfoResult{BucketInfo: *client.bucketInfo}, nil
}

func (client *fakeOSSClient) GetBucketLogging(context.Context, *osssdk.GetBucketLoggingRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketLoggingResult, error) {
	if client.logging == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketLoggingResult{BucketLoggingStatus: &osssdk.BucketLoggingStatus{LoggingEnabled: client.logging}}, nil
}

func (client *fakeOSSClient) GetBucketPolicy(context.Context, *osssdk.GetBucketPolicyRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketPolicyResult, error) {
	if client.policyBody == "" {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketPolicyResult{Body: client.policyBody}, nil
}

func (client *fakeOSSClient) GetBucketPolicyStatus(context.Context, *osssdk.GetBucketPolicyStatusRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketPolicyStatusResult, error) {
	if client.policyStatus == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketPolicyStatusResult{PolicyStatus: client.policyStatus}, nil
}

func (client *fakeOSSClient) GetBucketEncryption(context.Context, *osssdk.GetBucketEncryptionRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketEncryptionResult, error) {
	if client.encryption == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketEncryptionResult{ServerSideEncryptionRule: &osssdk.ServerSideEncryptionRule{ApplyServerSideEncryptionByDefault: client.encryption}}, nil
}

func (client *fakeOSSClient) GetBucketVersioning(context.Context, *osssdk.GetBucketVersioningRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketVersioningResult, error) {
	if client.versioning == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketVersioningResult{VersionStatus: client.versioning}, nil
}

func (client *fakeOSSClient) GetBucketReferer(context.Context, *osssdk.GetBucketRefererRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketRefererResult, error) {
	if client.referer == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketRefererResult{RefererConfiguration: client.referer}, nil
}

func (client *fakeOSSClient) GetBucketCors(context.Context, *osssdk.GetBucketCorsRequest, ...func(*osssdk.Options)) (*osssdk.GetBucketCorsResult, error) {
	if client.cors == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.GetBucketCorsResult{CORSConfiguration: client.cors}, nil
}

func (client *fakeOSSClient) ListBucketInventory(context.Context, *osssdk.ListBucketInventoryRequest, ...func(*osssdk.Options)) (*osssdk.ListBucketInventoryResult, error) {
	if client.inventory == nil {
		return nil, errors.New("not configured")
	}
	return &osssdk.ListBucketInventoryResult{
		ListInventoryConfigurationsResult: &osssdk.ListInventoryConfigurationsResult{
			InventoryConfigurations: client.inventory,
			IsTruncated:             osssdk.Ptr(false),
		},
	}, nil
}

type recordingCollector struct {
	resourceTypes string
	assets        []liteprovider.Asset
}

func (collector *recordingCollector) Collect(_ context.Context, account liteprovider.Account, _ Credentials) ([]liteprovider.Asset, error) {
	collector.resourceTypes = account.Config["resource_types"]
	return collector.assets, nil
}

func mapValue(t *testing.T, values map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := values[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, values[key])
	}
	return value
}

func sliceValue(t *testing.T, values map[string]any, key string) []any {
	t.Helper()
	value, ok := values[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v, want array", key, values[key])
	}
	return value
}

func containsAnyString(values []any, want string) bool {
	return slices.ContainsFunc(values, func(value any) bool {
		text, _ := value.(string)
		return text == want
	})
}
