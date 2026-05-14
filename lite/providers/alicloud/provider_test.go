package alicloud

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/antgroup/CloudRec/lite/internal/progress"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
	coreschema "github.com/core-sdk/schema"
	keyring "github.com/zalando/go-keyring"
)

func TestResolveCredentialsPrefersAccountCredentials(t *testing.T) {
	t.Setenv(EnvAccessKeyID, "env-ak")
	t.Setenv(EnvAccessKeySecret, "env-sk")
	t.Setenv(EnvRegion, "cn-beijing")

	credentials, err := ResolveCredentials(liteprovider.Account{
		DefaultRegion: "cn-hangzhou",
		Credentials: map[string]string{
			"access_key_id":     "account-ak",
			"access_key_secret": "account-sk",
		},
	})
	if err != nil {
		t.Fatalf("ResolveCredentials returned error: %v", err)
	}

	if credentials.AccessKeyID != "account-ak" {
		t.Fatalf("AccessKeyID = %q, want account-ak", credentials.AccessKeyID)
	}
	if credentials.AccessKeySecret != "account-sk" {
		t.Fatalf("AccessKeySecret = %q, want account-sk", credentials.AccessKeySecret)
	}
	if credentials.Region != "cn-hangzhou" {
		t.Fatalf("Region = %q, want cn-hangzhou", credentials.Region)
	}
}

func TestResolveCredentialsFallsBackToEnvironment(t *testing.T) {
	t.Setenv(EnvAccessKeyID, "env-ak")
	t.Setenv(EnvAccessKeySecret, "env-sk")
	t.Setenv(EnvRegion, "cn-shanghai")

	credentials, err := ResolveCredentials(liteprovider.Account{
		Config: map[string]string{
			ConfigCredentialSource: CredentialSourceEnv,
		},
	})
	if err != nil {
		t.Fatalf("ResolveCredentials returned error: %v", err)
	}

	if credentials.AccessKeyID != "env-ak" {
		t.Fatalf("AccessKeyID = %q, want env-ak", credentials.AccessKeyID)
	}
	if credentials.AccessKeySecret != "env-sk" {
		t.Fatalf("AccessKeySecret = %q, want env-sk", credentials.AccessKeySecret)
	}
	if credentials.Region != "cn-shanghai" {
		t.Fatalf("Region = %q, want cn-shanghai", credentials.Region)
	}
}

func TestResolveCredentialsReadsSystemCredentialStore(t *testing.T) {
	keyring.MockInit()
	t.Setenv(EnvAccessKeyID, "")
	t.Setenv(EnvAccessKeySecret, "")
	t.Setenv(EnvRegion, "")

	if err := StoreCredentialProfile("unit-profile", Credentials{
		AccessKeyID:     "stored-ak",
		AccessKeySecret: "stored-sk",
		SecurityToken:   "stored-token",
		Region:          "cn-hangzhou",
	}); err != nil {
		t.Fatalf("store credential profile: %v", err)
	}

	credentials, err := ResolveCredentials(liteprovider.Account{
		Config: map[string]string{
			ConfigCredentialSource:  CredentialSourceKeyring,
			ConfigCredentialProfile: "unit-profile",
		},
	})
	if err != nil {
		t.Fatalf("ResolveCredentials returned error: %v", err)
	}
	if credentials.AccessKeyID != "stored-ak" || credentials.AccessKeySecret != "stored-sk" {
		t.Fatalf("unexpected stored credentials: %+v", credentials)
	}
	if credentials.SecurityToken != "stored-token" {
		t.Fatalf("SecurityToken = %q, want stored-token", credentials.SecurityToken)
	}
	if credentials.Region != "cn-hangzhou" {
		t.Fatalf("Region = %q, want cn-hangzhou", credentials.Region)
	}
}

func TestResolveCredentialsReadsLocalCredentialFile(t *testing.T) {
	t.Setenv(EnvCredentialDir, t.TempDir())
	t.Setenv(EnvAccessKeyID, "")
	t.Setenv(EnvAccessKeySecret, "")
	t.Setenv(EnvRegion, "")

	status, err := StoreFileCredentialProfile("file-profile", Credentials{
		AccessKeyID:     "file-ak",
		AccessKeySecret: "file-sk",
		SecurityToken:   "file-token",
		Region:          "cn-hangzhou",
	})
	if err != nil {
		t.Fatalf("store local credential file: %v", err)
	}
	if status.Backend != credentialBackendFile || status.Path == "" {
		t.Fatalf("unexpected local file status: %+v", status)
	}
	content, err := os.ReadFile(status.Path)
	if err != nil {
		t.Fatalf("read local credential file: %v", err)
	}
	if bytes.Contains(content, []byte("file-ak")) || bytes.Contains(content, []byte("file-sk")) {
		t.Fatalf("local credential file contains plaintext credentials: %s", string(content))
	}

	credentials, err := ResolveCredentials(liteprovider.Account{
		Config: map[string]string{
			ConfigCredentialSource:  CredentialSourceFile,
			ConfigCredentialProfile: "file-profile",
		},
	})
	if err != nil {
		t.Fatalf("ResolveCredentials returned error: %v", err)
	}
	if credentials.AccessKeyID != "file-ak" || credentials.AccessKeySecret != "file-sk" {
		t.Fatalf("unexpected file credentials: %+v", credentials)
	}
	if credentials.SecurityToken != "file-token" || credentials.Region != "cn-hangzhou" {
		t.Fatalf("unexpected token or region: %+v", credentials)
	}
}

func TestResolveCredentialsAutoPrefersSystemCredentialStore(t *testing.T) {
	keyring.MockInit()
	t.Setenv(EnvAccessKeyID, "env-ak")
	t.Setenv(EnvAccessKeySecret, "env-sk")
	t.Setenv(EnvRegion, "cn-shanghai")

	if err := StoreCredentialProfile("default", Credentials{
		AccessKeyID:     "stored-ak",
		AccessKeySecret: "stored-sk",
		Region:          "cn-hangzhou",
	}); err != nil {
		t.Fatalf("store credential profile: %v", err)
	}

	credentials, err := ResolveCredentials(liteprovider.Account{})
	if err != nil {
		t.Fatalf("ResolveCredentials returned error: %v", err)
	}
	if credentials.AccessKeyID != "stored-ak" || credentials.AccessKeySecret != "stored-sk" {
		t.Fatalf("expected keyring credentials before env fallback, got %+v", credentials)
	}
	if credentials.Region != "cn-hangzhou" {
		t.Fatalf("Region = %q, want cn-hangzhou", credentials.Region)
	}
}

func TestResolveCredentialsKeyringMissingReturnsActionableError(t *testing.T) {
	keyring.MockInit()
	t.Setenv(EnvAccessKeyID, "")
	t.Setenv(EnvAccessKeySecret, "")

	_, err := ResolveCredentials(liteprovider.Account{
		AccountID: "123456789",
		Config: map[string]string{
			ConfigCredentialSource: CredentialSourceKeyring,
		},
	})
	if err == nil {
		t.Fatal("expected missing keyring credential error")
	}
	message := err.Error()
	if !strings.Contains(message, "123456789") || !strings.Contains(message, "credentials store") {
		t.Fatalf("expected actionable missing credential hint, got %q", message)
	}
}

func TestCredentialProfileUsesConfigThenAccountThenDefault(t *testing.T) {
	if got := CredentialProfile(liteprovider.Account{
		AccountID: "account-id",
		Config: map[string]string{
			ConfigCredentialProfile: "configured-profile",
		},
	}); got != "configured-profile" {
		t.Fatalf("CredentialProfile with config = %q", got)
	}
	if got := CredentialProfile(liteprovider.Account{AccountID: "account-id"}); got != "account-id" {
		t.Fatalf("CredentialProfile with account = %q", got)
	}
	if got := CredentialProfile(liteprovider.Account{}); got != DefaultCredentialProfile {
		t.Fatalf("CredentialProfile default = %q", got)
	}
}

func TestValidateAccountAllowsFixtureWithoutCredentials(t *testing.T) {
	t.Setenv(EnvAccessKeyID, "")
	t.Setenv(EnvAccessKeySecret, "")

	err := New().ValidateAccount(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Config: map[string]string{
			"fixture": "input.json",
		},
	})
	if err != nil {
		t.Fatalf("ValidateAccount returned error: %v", err)
	}
}

func TestCollectAssetsFromLegacyFixture(t *testing.T) {
	fixtureDir := t.TempDir()
	writeFile(t, filepath.Join(fixtureDir, "metadata.json"), `{
		"platform": "ALI_CLOUD",
		"resourceType": "OSS",
		"code": "ALI_CLOUD_OSS_202503031646_805434"
	}`)
	writeFile(t, filepath.Join(fixtureDir, "input.json"), `{
		"BucketProperties": {
			"Name": "bucket-demo",
			"Region": "cn-hangzhou"
		},
		"LoggingEnabled": null,
		"Tags": {
			"Tag": [
				{"Key": "env", "Value": "dev"},
				{"TagKey": "owner", "TagValue": "security"}
			]
		}
	}`)

	assets, err := New().CollectAssets(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Config: map[string]string{
			"fixture": fixtureDir,
		},
	})
	if err != nil {
		t.Fatalf("CollectAssets returned error: %v", err)
	}

	if len(assets) != 1 {
		t.Fatalf("len(assets) = %d, want 1", len(assets))
	}

	asset := assets[0]
	if asset.Provider != ProviderName {
		t.Fatalf("Provider = %q, want %q", asset.Provider, ProviderName)
	}
	if asset.Type != "OSS" {
		t.Fatalf("Type = %q, want OSS", asset.Type)
	}
	if asset.Name != "bucket-demo" {
		t.Fatalf("Name = %q, want bucket-demo", asset.Name)
	}
	if asset.Region != "cn-hangzhou" {
		t.Fatalf("Region = %q, want cn-hangzhou", asset.Region)
	}
	if asset.ID != "alicloud://123456789/cn-hangzhou/OSS/bucket-demo" {
		t.Fatalf("ID = %q, want stable alicloud id", asset.ID)
	}
	if asset.Tags["env"] != "dev" || asset.Tags["owner"] != "security" {
		t.Fatalf("Tags = %#v, want env and owner tags", asset.Tags)
	}
	if _, ok := asset.Properties["LoggingEnabled"]; !ok {
		t.Fatalf("Properties missing legacy LoggingEnabled key: %#v", asset.Properties)
	}
}

func TestCollectAssetsWithoutFixtureUsesCollectorSeam(t *testing.T) {
	collector := fakeCollector{
		assets: []liteprovider.Asset{{ID: "asset-1", Type: "ECS"}},
	}
	assets, err := New(WithCollector(collector), WithAccountValidator(noopAccountValidator{})).CollectAssets(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Credentials: map[string]string{
			EnvAccessKeyID:     "ak",
			EnvAccessKeySecret: "sk",
		},
	})
	if err != nil {
		t.Fatalf("CollectAssets returned error: %v", err)
	}
	if len(assets) != 1 || assets[0].ID != "asset-1" {
		t.Fatalf("assets = %#v, want fake collector asset", assets)
	}
}

func TestCollectAssetsRejectsInvalidCollectorLogLevel(t *testing.T) {
	_, err := New(WithCollector(fakeCollector{}), WithAccountValidator(noopAccountValidator{})).CollectAssets(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Credentials: map[string]string{
			EnvAccessKeyID:     "ak",
			EnvAccessKeySecret: "sk",
		},
		Config: map[string]string{
			"collector_log_level": "verbose",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid collector log level") {
		t.Fatalf("error = %v, want invalid collector log level", err)
	}
}

func TestCollectorTimeoutRejectsInvalidValue(t *testing.T) {
	_, err := New(WithCollector(fakeCollector{}), WithAccountValidator(noopAccountValidator{})).CollectAssets(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Credentials: map[string]string{
			EnvAccessKeyID:     "ak",
			EnvAccessKeySecret: "sk",
		},
		Config: map[string]string{
			"collector_timeout": "fast",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid collector timeout") {
		t.Fatalf("error = %v, want invalid collector timeout", err)
	}
}

func TestCollectorConcurrencyRejectsInvalidValue(t *testing.T) {
	_, err := New(WithCollector(fakeCollector{}), WithAccountValidator(noopAccountValidator{})).CollectAssets(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Credentials: map[string]string{
			EnvAccessKeyID:     "ak",
			EnvAccessKeySecret: "sk",
		},
		Config: map[string]string{
			"collector_concurrency": "0",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid collector concurrency") {
		t.Fatalf("error = %v, want invalid collector concurrency", err)
	}
}

func TestClassifyCollectionError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"timeout": {
			err:  context.DeadlineExceeded,
			want: "timeout",
		},
		"unsupported": {
			err:  fmt.Errorf("%w: SLB", ErrResourceAdapterNotImplemented),
			want: "unsupported",
		},
		"throttling": {
			err:  errors.New("Throttling.User qps exceeded"),
			want: "throttling",
		},
		"permission": {
			err:  errors.New("Forbidden: AccessDenied"),
			want: "permission",
		},
		"expected absent login profile": {
			err:  errors.New("EntityNotExist.User.LoginProfile: login profile does not exist"),
			want: "expected_absent",
		},
		"product not enabled": {
			err:  errors.New("ServiceNotEnabled: resource center is not enabled"),
			want: "product_not_enabled",
		},
		"service disabled": {
			err:  errors.New("InvalidIdentity.ServiceDisabled: live service disabled"),
			want: "product_not_enabled",
		},
		"unsupported region": {
			err:  errors.New("NotSupportedEndpoint: specified endpoint cant operate this region"),
			want: "unsupported_region",
		},
		"kms unsupported operation": {
			err:  errors.New("UnsupportedOperation: This action is not supported"),
			want: "unsupported_region",
		},
		"aliyuncs endpoint dns failure": {
			err:  errors.New(`Post "https://apig.cn-fuzhou.aliyuncs.com/": dial tcp: lookup apig.cn-fuzhou.aliyuncs.com: no such host`),
			want: "unsupported_region",
		},
		"collector request": {
			err:  errors.New("MissingFunctionNames: FunctionNames is mandatory"),
			want: "collector_request",
		},
		"collector request invalid action": {
			err:  errors.New("InvalidAction.NotFound: Specified api is not found"),
			want: "collector_request",
		},
		"collector request code beats generic server message": {
			err:  errors.New("SDK.ServerError\nErrorCode: MissingNextToken\nMessage: NextToken is mandatory for the first page."),
			want: "collector_request",
		},
		"product disabled code beats generic server message": {
			err:  errors.New("SDK.ServerError\nErrorCode: InvalidIdentity.ServiceDisabled\nMessage: The service is disabled."),
			want: "product_not_enabled",
		},
		"maxcompute tenant required": {
			err:  errors.New("SDKError:\n   StatusCode: 400\n   Code: ILLEGAL_REQUEST\n   Message: Tenant id is empty."),
			want: "collector_request",
		},
		"transient": {
			err:  errors.New("ServiceUnavailable: temporary failure in name resolution"),
			want: "transient",
		},
		"network": {
			err:  errors.New("dial tcp: no such host"),
			want: "network",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := classifyCollectionError(tc.err); got != tc.want {
				t.Fatalf("classifyCollectionError() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeCollectionMessageRedactsCredentials(t *testing.T) {
	accessKeyID := "LT" + "AI5abcdef123456"
	standaloneAccessKeyID := "LT" + "AI5standalone1234567890"
	input := fmt.Sprintf(`Post "https://ecs.aliyuncs.com/?AccessKeyId=%s&Signature=abcdef&SecurityToken=token" {"AccessKeySecret":"secret","Signature":"jsonsig"} standalone=%s`, accessKeyID, standaloneAccessKeyID)
	output := sanitizeCollectionMessage(input)

	for _, leak := range []string{accessKeyID, standaloneAccessKeyID, "Signature=abcdef", "SecurityToken=token", `"AccessKeySecret":"secret"`, `"Signature":"jsonsig"`} {
		if strings.Contains(output, leak) {
			t.Fatalf("sanitized output still contains %q: %s", leak, output)
		}
	}
}

func TestApplyRegionMatrixAvoidsDefaultRegionOmission(t *testing.T) {
	cases := map[string]struct {
		resourceType string
		regions      []string
		explicit     bool
		want         []string
	}{
		"single endpoint resource collapses default scan": {
			resourceType: "CDN",
			regions:      []string{"cn-beijing", "cn-shanghai", "cn-hangzhou"},
			want:         []string{"cn-hangzhou"},
		},
		"dcdn domain uses account-level endpoint": {
			resourceType: "DCDN Domain",
			regions:      []string{"cn-beijing", "cn-shanghai", "ap-southeast-1"},
			want:         []string{"cn-hangzhou"},
		},
		"dns uses account-level endpoint": {
			resourceType: "DNS",
			regions:      []string{"cn-beijing", "cn-shanghai", "ap-southeast-1"},
			want:         []string{"cn-hangzhou"},
		},
		"dms uses tenant-level endpoint": {
			resourceType: "DMS",
			regions:      []string{"cn-beijing", "cn-shanghai", "ap-southeast-1"},
			want:         []string{"cn-hangzhou"},
		},
		"explicit user region bypasses matrix": {
			resourceType: "CDN",
			regions:      []string{"cn-beijing"},
			explicit:     true,
			want:         []string{"cn-beijing"},
		},
		"unknown resource preserves future regions": {
			resourceType: "New Aliyun Product",
			regions:      []string{"cn-hangzhou", "cn-new-region-1"},
			want:         []string{"cn-hangzhou", "cn-new-region-1"},
		},
		"exclude rule removes only known bad regions": {
			resourceType: "MSE Cluster",
			regions:      []string{"cn-hangzhou", "cn-zhengzhou-jva", "cn-new-region-1"},
			want:         []string{"cn-hangzhou", "cn-new-region-1"},
		},
		"kms excludes observed unsupported regions": {
			resourceType: "KMS",
			regions:      []string{"cn-hangzhou", "cn-fuzhou", "cn-wuhan-lr", "cn-zhengzhou-jva", "na-south-1", "cn-hangzhou-finance", "cn-new-region-1"},
			want:         []string{"cn-hangzhou", "cn-new-region-1"},
		},
		"explicit excluded region bypasses matrix": {
			resourceType: "KMS",
			regions:      []string{"cn-fuzhou"},
			explicit:     true,
			want:         []string{"cn-fuzhou"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := applyRegionMatrix(tc.resourceType, tc.regions, tc.explicit)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("applyRegionMatrix() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestRegistryCollectorWithoutAdaptersReturnsNotImplemented(t *testing.T) {
	_, err := New(WithCollector(NewRegistryCollector()), WithAccountValidator(noopAccountValidator{})).CollectAssets(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Credentials: map[string]string{
			EnvAccessKeyID:     "ak",
			EnvAccessKeySecret: "sk",
		},
	})
	if !errors.Is(err, ErrSDKCollectionNotImplemented) {
		t.Fatalf("error = %v, want ErrSDKCollectionNotImplemented", err)
	}
}

func TestCapabilitiesCoverExistingAliCloudRuleResourceTypes(t *testing.T) {
	capabilities := New().Capabilities()

	if got, want := len(capabilities.AssetTypes), 100; got != want {
		t.Fatalf("Capabilities.AssetTypes length = %d, want %d", got, want)
	}
	for _, assetType := range []string{"OSS", "ECS", "RAM User", "SLB", "ACK Cluster", "CloudStorageGateway", "OpenSearch AppGroup", "Cloudfw", "Sas", "MSE"} {
		if !contains(capabilities.AssetTypes, assetType) {
			t.Fatalf("Capabilities.AssetTypes missing %q: %#v", assetType, capabilities.AssetTypes)
		}
	}
	if !capabilities.SupportsAccountValidation {
		t.Fatal("SupportsAccountValidation = false, want true")
	}
	if capabilities.MaxConcurrency <= 0 {
		t.Fatalf("MaxConcurrency = %d, want positive value", capabilities.MaxConcurrency)
	}
}

func TestAllResourceSpecsCoverCollectorCatalog(t *testing.T) {
	specs := AllResourceSpecs()
	if got, want := len(specs), 100; got != want {
		t.Fatalf("AllResourceSpecs length = %d, want %d", got, want)
	}

	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.Type == "" {
			t.Fatalf("spec has empty Type: %#v", spec)
		}
		if spec.Normalized == "" {
			t.Fatalf("spec %q has empty Normalized", spec.Type)
		}
		if spec.Dimension != DimensionGlobal && spec.Dimension != DimensionRegional {
			t.Fatalf("spec %q has invalid dimension %q", spec.Type, spec.Dimension)
		}
		if spec.CollectorPath == "" {
			t.Fatalf("spec %q has empty CollectorPath", spec.Type)
		}
		if seen[spec.Type] {
			t.Fatalf("duplicate resource type %q", spec.Type)
		}
		seen[spec.Type] = true
	}
}

func TestLegacyCollectorCoversAllCatalogResourceTypes(t *testing.T) {
	resources := NewLegacyCollector().resourcesByType()

	for _, spec := range AllResourceSpecs() {
		if _, ok := resources[normalizeResourceType(spec.Type)]; !ok {
			t.Fatalf("legacy collector missing catalog resource type %q", spec.Type)
		}
	}
}

func TestAssetFromLegacyDataUsesResourceRowFields(t *testing.T) {
	asset, err := assetFromLegacyData(liteprovider.Account{
		AccountID: "123456789",
	}, coreschema.Resource{
		ResourceType: "OSS",
		RowField: coreschema.RowField{
			ResourceId:   "$.BucketProperties.Name",
			ResourceName: "$.BucketProperties.Name",
		},
		Dimension: coreschema.Global,
	}, "cn-hangzhou", map[string]any{
		"BucketProperties": map[string]any{
			"Name":   "bucket-demo",
			"Region": "cn-shanghai",
		},
		"Tags": map[string]any{
			"Tag": []any{
				map[string]any{"Key": "env", "Value": "dev"},
			},
		},
	})
	if err != nil {
		t.Fatalf("assetFromLegacyData returned error: %v", err)
	}
	if asset.ID != "alicloud://123456789/cn-shanghai/OSS/bucket-demo" {
		t.Fatalf("ID = %q, want stable legacy asset id", asset.ID)
	}
	if asset.Region != "cn-shanghai" {
		t.Fatalf("Region = %q, want cn-shanghai", asset.Region)
	}
	if asset.Tags["env"] != "dev" {
		t.Fatalf("Tags = %#v, want env tag", asset.Tags)
	}
}

func TestSpecsForAccountFiltersResourceTypes(t *testing.T) {
	specs := specsForAccount(liteprovider.Account{
		Config: map[string]string{
			"resource_types": "OSS, ECS, RAM User",
		},
	})

	got := make([]string, 0, len(specs))
	for _, spec := range specs {
		got = append(got, spec.Type)
	}
	want := []string{"ECS", "OSS", "RAM User"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("filtered specs = %#v, want %#v", got, want)
	}
}

func TestLegacyCollectorPreservesAssetsWhenResourceReturnsError(t *testing.T) {
	collector := NewLegacyCollector(
		WithLegacyService(fakeLegacyService{}),
		WithLegacyDefaultRegions([]string{"cn-hangzhou"}),
		WithLegacyResources([]coreschema.Resource{{
			ResourceType: "OSS",
			RowField: coreschema.RowField{
				ResourceId:   "$.id",
				ResourceName: "$.name",
			},
			Dimension: coreschema.Regional,
			ResourceDetailFunc: func(ctx context.Context, service coreschema.ServiceInterface, res chan<- any) error {
				res <- map[string]any{
					"id":   "oss-1",
					"name": "oss-1",
				}
				return errors.New("tail failure")
			},
		}}),
	)

	assets, err := collector.Collect(context.Background(), liteprovider.Account{
		AccountID: "123456789",
		Config: map[string]string{
			"resource_types":        "OSS",
			"collector_concurrency": "1",
		},
	}, Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"})
	if err == nil {
		t.Fatal("expected partial collection error")
	}
	var partial *liteprovider.PartialCollectionError
	if !errors.As(err, &partial) {
		t.Fatalf("error = %T, want PartialCollectionError", err)
	}
	if len(assets) != 1 || len(partial.Assets) != 1 {
		t.Fatalf("assets = %#v, partial assets = %#v, want preserved asset", assets, partial.Assets)
	}
	if assets[0].ID != "alicloud://123456789/cn-hangzhou/OSS/oss-1" {
		t.Fatalf("asset ID = %q, want stable legacy asset ID", assets[0].ID)
	}
}

func TestLegacyCollectorReportsResourceRegionProgress(t *testing.T) {
	collector := NewLegacyCollector(
		WithLegacyService(fakeLegacyService{}),
		WithLegacyDefaultRegions([]string{"cn-hangzhou", "cn-shanghai"}),
		WithLegacyResources([]coreschema.Resource{{
			ResourceType: "OSS",
			RowField: coreschema.RowField{
				ResourceId:   "$.id",
				ResourceName: "$.name",
			},
			Dimension: coreschema.Regional,
			ResourceDetailFunc: func(ctx context.Context, service coreschema.ServiceInterface, res chan<- any) error {
				res <- map[string]any{
					"id":   "oss-1",
					"name": "oss-1",
				}
				return nil
			},
		}}),
	)

	var output bytes.Buffer
	ctx := progress.WithReporter(context.Background(), progress.NewReporter(&output))
	_, err := collector.Collect(ctx, liteprovider.Account{
		AccountID: "123456789",
		Config: map[string]string{
			"resource_types": "OSS",
		},
	}, Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	for _, want := range []string{
		"[progress] alicloud legacy collector",
		"current=\"OSS@cn-hangzhou\"",
		"pending=\"OSS@cn-shanghai\"",
		"eta=",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("progress output missing %q:\n%s", want, output.String())
		}
	}
}

func TestLegacyCollectorConvertsResourcePanicToPartialFailure(t *testing.T) {
	collector := NewLegacyCollector(
		WithLegacyService(fakeLegacyService{}),
		WithLegacyDefaultRegions([]string{"cn-hangzhou"}),
		WithLegacyResources([]coreschema.Resource{{
			ResourceType: "OSS",
			RowField: coreschema.RowField{
				ResourceId:   "$.id",
				ResourceName: "$.name",
			},
			Dimension: coreschema.Regional,
			ResourceDetailFunc: func(ctx context.Context, service coreschema.ServiceInterface, res chan<- any) error {
				res <- map[string]any{
					"id":   "oss-1",
					"name": "oss-1",
				}
				panic("boom")
			},
		}}),
	)

	assets, err := collector.Collect(context.Background(), liteprovider.Account{
		AccountID: "123456789",
		Config: map[string]string{
			"resource_types": "OSS",
		},
	}, Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"})
	if err == nil {
		t.Fatal("expected partial collection error")
	}
	var partial *liteprovider.PartialCollectionError
	if !errors.As(err, &partial) {
		t.Fatalf("error = %T, want PartialCollectionError", err)
	}
	if !strings.Contains(err.Error(), "legacy collector panic: boom") {
		t.Fatalf("error = %v, want panic details", err)
	}
	if len(assets) != 1 || len(partial.Assets) != 1 {
		t.Fatalf("assets = %#v, partial assets = %#v, want preserved asset", assets, partial.Assets)
	}
}

func TestRegistryCollectorUsesResourceAdapters(t *testing.T) {
	collector := NewRegistryCollector(WithResourceAdapter(fakeResourceAdapter{
		spec: ResourceSpec{
			Type:      "OSS",
			Group:     "STORE",
			Dimension: DimensionGlobal,
		},
		assets: []liteprovider.Asset{{ID: "oss-1", Type: "OSS"}},
	}))

	assets, err := collector.Collect(context.Background(), liteprovider.Account{
		AccountID: "123456789",
		Config: map[string]string{
			"resource_types": "OSS",
		},
	}, Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(assets) != 1 || assets[0].ID != "oss-1" {
		t.Fatalf("assets = %#v, want fake resource adapter asset", assets)
	}
}

func TestRegistryCollectorReportsUnimplementedSelectedResources(t *testing.T) {
	_, err := NewRegistryCollector().Collect(context.Background(), liteprovider.Account{
		AccountID: "123456789",
		Config: map[string]string{
			"resource_types": "OSS",
		},
	}, Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"})
	if !errors.Is(err, ErrSDKCollectionNotImplemented) {
		t.Fatalf("error = %v, want ErrSDKCollectionNotImplemented", err)
	}
}

func TestValidateAccountCanSkipLiveValidation(t *testing.T) {
	err := New(WithAccountValidator(failingAccountValidator{})).ValidateAccount(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Config: map[string]string{
			"skip_account_validation": "true",
		},
		Credentials: map[string]string{
			EnvAccessKeyID:     "ak",
			EnvAccessKeySecret: "sk",
		},
	})
	if err != nil {
		t.Fatalf("ValidateAccount returned error: %v", err)
	}
}

func TestValidateAccountRunsLiveValidatorByDefault(t *testing.T) {
	err := New(WithAccountValidator(failingAccountValidator{})).ValidateAccount(context.Background(), liteprovider.Account{
		Provider:  ProviderName,
		AccountID: "123456789",
		Credentials: map[string]string{
			EnvAccessKeyID:     "ak",
			EnvAccessKeySecret: "sk",
		},
	})
	if err == nil {
		t.Fatal("expected validator error")
	}
}

type fakeCollector struct {
	assets []liteprovider.Asset
}

func (collector fakeCollector) Collect(context.Context, liteprovider.Account, Credentials) ([]liteprovider.Asset, error) {
	return collector.assets, nil
}

type fakeResourceAdapter struct {
	spec   ResourceSpec
	assets []liteprovider.Asset
}

type noopAccountValidator struct{}

func (noopAccountValidator) Validate(context.Context, liteprovider.Account, Credentials) error {
	return nil
}

type failingAccountValidator struct{}

func (failingAccountValidator) Validate(context.Context, liteprovider.Account, Credentials) error {
	return errors.New("validator failed")
}

type fakeLegacyService struct{}

func (fakeLegacyService) InitServices(coreschema.CloudAccountParam) error {
	return nil
}

func (fakeLegacyService) Clone() coreschema.ServiceInterface {
	return fakeLegacyService{}
}

func (fakeLegacyService) AssessCollectionTrigger(coreschema.CloudAccountParam) coreschema.CollectRecordInfo {
	return coreschema.CollectRecordInfo{EnableCollection: true}
}

func (adapter fakeResourceAdapter) Spec() ResourceSpec {
	return adapter.spec
}

func (adapter fakeResourceAdapter) Collect(context.Context, AdapterRequest) ([]liteprovider.Asset, error) {
	return adapter.assets, nil
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
