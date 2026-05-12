package alicloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	alb20200616 "github.com/alibabacloud-go/alb-20200616/v2/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	das20200116 "github.com/alibabacloud-go/das-20200116/v3/client"
	dds20151201 "github.com/alibabacloud-go/dds-20151201/v8/client"
	ims20190815 "github.com/alibabacloud-go/ims-20190815/v4/client"
	nlb20220430 "github.com/alibabacloud-go/nlb-20220430/v3/client"
	r_kvstore20150101 "github.com/alibabacloud-go/r-kvstore-20150101/v5/client"
	ram20150501 "github.com/alibabacloud-go/ram-20150501/v2/client"
	rds20140815 "github.com/alibabacloud-go/rds-20140815/v6/client"
	slb20140515 "github.com/alibabacloud-go/slb-20140515/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	aliecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	alivpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
	legacycollector "github.com/cloudrec/alicloud/collector"
	legacymongodb "github.com/cloudrec/alicloud/collector/db/mongodb"
	legacyrds "github.com/cloudrec/alicloud/collector/db/rds"
	legacyecs "github.com/cloudrec/alicloud/collector/ecs"
	legacyalb "github.com/cloudrec/alicloud/collector/loadbalance/alb"
	legacynlb "github.com/cloudrec/alicloud/collector/loadbalance/nlb"
	legacyslb "github.com/cloudrec/alicloud/collector/loadbalance/slb"
	legacyram "github.com/cloudrec/alicloud/collector/ram"
	legacyredis "github.com/cloudrec/alicloud/collector/redis"
	coreconstant "github.com/core-sdk/constant"
	coreschema "github.com/core-sdk/schema"
)

type resourceServiceFactory func(AdapterRequest, coreschema.Resource, string) (coreschema.ServiceInterface, error)

type relationshipExtractor func(liteprovider.Account, coreschema.Resource, string, map[string]any) []liteprovider.Relationship

type ResourceFunctionAdapter struct {
	spec                  ResourceSpec
	resource              coreschema.Resource
	serviceFactory        resourceServiceFactory
	relationshipExtractor relationshipExtractor
}

type ResourceFunctionAdapterOption func(*ResourceFunctionAdapter)

func NewResourceFunctionAdapter(resource coreschema.Resource, options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	adapter := &ResourceFunctionAdapter{
		spec:           specForResourceType(resource.ResourceType),
		resource:       resource,
		serviceFactory: defaultResourceServiceFactory,
	}
	for _, option := range options {
		option(adapter)
	}
	return adapter
}

func WithResourceFunctionServiceFactory(factory resourceServiceFactory) ResourceFunctionAdapterOption {
	return func(adapter *ResourceFunctionAdapter) {
		if factory != nil {
			adapter.serviceFactory = factory
		}
	}
}

func WithResourceFunctionResource(resource coreschema.Resource) ResourceFunctionAdapterOption {
	return func(adapter *ResourceFunctionAdapter) {
		if resource.ResourceType != "" {
			adapter.resource = resource
			adapter.spec = specForResourceType(resource.ResourceType)
		}
	}
}

func WithRelationshipExtractor(extractor relationshipExtractor) ResourceFunctionAdapterOption {
	return func(adapter *ResourceFunctionAdapter) {
		adapter.relationshipExtractor = extractor
	}
}

func (a *ResourceFunctionAdapter) Spec() ResourceSpec {
	return a.spec
}

func (a *ResourceFunctionAdapter) Collect(ctx context.Context, request AdapterRequest) ([]liteprovider.Asset, error) {
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	timeout = resourceFunctionTimeout(request, a.resource.ResourceType, timeout)

	regions := request.Regions
	if len(regions) == 0 {
		regions = []string{firstNonEmpty(request.Credentials.Region, "cn-hangzhou")}
	}
	if a.spec.Dimension == DimensionGlobal && len(regions) > 1 {
		regions = regions[:1]
	}

	var assets []liteprovider.Asset
	var failures []liteprovider.CollectionFailure
	for _, region := range regions {
		collected, err := a.collectRegion(ctx, request, region, timeout)
		assets = append(assets, collected...)
		if err != nil {
			failures = append(failures, resourceFailure(a.resource.ResourceType, region, err))
		}
	}
	return assets, partialCollectionError(assets, failures)
}

func resourceFunctionTimeout(request AdapterRequest, resourceType string, timeout time.Duration) time.Duration {
	if stringFromStringMap(request.Account.Config, collectorTimeoutConfigKey, "collectorTimeout") != "" {
		return timeout
	}
	switch normalizeResourceType(resourceType) {
	case "ram_user", "ram_role":
		if timeout < 90*time.Second {
			return 90 * time.Second
		}
	}
	return timeout
}

func (a *ResourceFunctionAdapter) collectRegion(ctx context.Context, request AdapterRequest, region string, timeout time.Duration) ([]liteprovider.Asset, error) {
	service, err := a.serviceFactory(request, a.resource, region)
	if err != nil {
		return nil, err
	}

	regionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	regionCtx = context.WithValue(regionCtx, coreconstant.CloudAccountId, request.Account.AccountID)
	regionCtx = context.WithValue(regionCtx, coreconstant.CloudAccountConfig, cloneStringConfig(request.Account.Config))
	regionCtx = context.WithValue(regionCtx, coreconstant.RegionId, region)
	regionCtx = context.WithValue(regionCtx, coreconstant.ResourceType, a.resource.ResourceType)

	dataCh := make(chan any, 50)
	errCh := make(chan error, 1)
	go func() {
		defer close(dataCh)
		if a.resource.ResourceDetailFunc != nil {
			errCh <- a.resource.ResourceDetailFunc(regionCtx, service, dataCh)
			return
		}
		if a.resource.ResourceDetailFuncWithCancel != nil {
			errCh <- a.resource.ResourceDetailFuncWithCancel(regionCtx, cancel, service, dataCh)
			return
		}
		errCh <- nil
	}()

	var assets []liteprovider.Asset
	done := regionCtx.Done()
	for dataCh != nil || errCh != nil {
		select {
		case data, ok := <-dataCh:
			if !ok {
				dataCh = nil
				continue
			}
			asset, err := a.assetFromData(request.Account, region, data)
			if err != nil {
				return assets, err
			}
			assets = append(assets, asset)
		case err := <-errCh:
			if err != nil {
				return assets, err
			}
			errCh = nil
		case <-done:
			if errors.Is(regionCtx.Err(), context.DeadlineExceeded) {
				return assets, fmt.Errorf("resource adapter timeout after %s", timeout)
			}
			done = nil
		}
	}
	return assets, nil
}

func (a *ResourceFunctionAdapter) assetFromData(account liteprovider.Account, region string, raw any) (liteprovider.Asset, error) {
	asset, err := assetFromLegacyData(account, a.resource, region, raw)
	if err != nil {
		return liteprovider.Asset{}, err
	}
	if a.relationshipExtractor != nil {
		asset.Relationships = a.relationshipExtractor(account, a.resource, asset.Region, asset.Properties)
	}
	return asset, nil
}

func NewRAMUserAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacyram.GetRAMUserResource(), options...)
}

func NewRAMRoleAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacyram.GetRAMRoleResource(), options...)
}

func NewECSAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	options = append([]ResourceFunctionAdapterOption{WithRelationshipExtractor(ecsSecurityGroupRelationships)}, options...)
	return NewResourceFunctionAdapter(legacyecs.GetInstanceResource(), options...)
}

func NewSecurityGroupAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacyecs.GetSecurityGroupData(), options...)
}

func NewSLBAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacyslb.GetSLBResource(), options...)
}

func NewALBAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacyalb.GetALBResource(), options...)
}

func NewNLBAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacynlb.GetNLBResource(), options...)
}

func NewRDSAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacyrds.GetRDSResource(), options...)
}

func NewRedisAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacyredis.GeRedisResource(), options...)
}

func NewMongoDBAdapter(options ...ResourceFunctionAdapterOption) *ResourceFunctionAdapter {
	return NewResourceFunctionAdapter(legacymongodb.GetMongoDBResource(), options...)
}

func defaultResourceServiceFactory(request AdapterRequest, resource coreschema.Resource, region string) (coreschema.ServiceInterface, error) {
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	sdkRegion := sdkRegionForCollection(request, region)
	config := newOpenAPIConfig(sdkRegion, request.Credentials, timeout)
	if proxy := firstNonEmpty(request.Account.Config["proxy"], request.Account.Config["proxy_config"]); proxy != "" {
		config.HttpProxy = tea.String(proxy)
		config.HttpsProxy = tea.String(proxy)
	}

	service := &legacycollector.Services{
		CloudAccountId: request.Account.AccountID,
		Config:         config,
	}

	switch normalizeResourceType(resource.ResourceType) {
	case "ecs", "security_group":
		client, err := newECSClient(sdkRegion, request.Credentials)
		if err != nil {
			return nil, err
		}
		setV1Proxy(client, request.Account.Config)
		service.ECS = client
	case "slb":
		client, err := newSLBClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		vpcClient, err := newVPCClient(sdkRegion, request.Credentials)
		if err != nil {
			return nil, err
		}
		setV1Proxy(vpcClient, request.Account.Config)
		service.SLB = client
		service.VPC = vpcClient
	case "alb":
		client, err := newALBClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		service.ALB = client
	case "nlb":
		client, err := newNLBClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		service.NLB = client
	case "ram_user", "ram_role":
		ramClient, err := newRAMClient("cn-hangzhou", config)
		if err != nil {
			return nil, err
		}
		imsClient, err := newIMSClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		service.RAM = ramClient
		service.IMS = imsClient
	case "rds":
		rdsClient, err := newRDSClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		dasClient, err := newDASClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		service.RDS = rdsClient
		service.DAS = dasClient
	case "redis":
		client, err := newRedisClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		service.Redis = client
	case "mongo_db":
		client, err := newMongoDBClient(sdkRegion, config)
		if err != nil {
			return nil, err
		}
		service.MongoDB = client
	default:
		return nil, fmt.Errorf("%w: %s", ErrResourceAdapterNotImplemented, resource.ResourceType)
	}
	return service, nil
}

func sdkRegionForCollection(request AdapterRequest, collectionRegion string) string {
	collectionRegion = strings.TrimSpace(collectionRegion)
	if collectionRegion != "" && collectionRegion != "global" {
		return collectionRegion
	}
	return firstNonEmpty(
		request.Credentials.Region,
		request.Account.DefaultRegion,
		request.Account.Config["region"],
		firstNonGlobal(request.Regions),
		"cn-hangzhou",
	)
}

func newOpenAPIConfig(region string, credentials Credentials, timeout time.Duration) *openapi.Config {
	config := &openapi.Config{
		AccessKeyId:     tea.String(credentials.AccessKeyID),
		AccessKeySecret: tea.String(credentials.AccessKeySecret),
		SecurityToken:   tea.String(credentials.SecurityToken),
		RegionId:        tea.String(region),
	}
	timeoutMS := int(timeout / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = 30000
	}
	config.SetConnectTimeout(timeoutMS)
	config.SetReadTimeout(timeoutMS)
	config.SetMaxIdleConns(100)
	return config
}

func newECSClient(region string, credentials Credentials) (*aliecs.Client, error) {
	if strings.TrimSpace(credentials.SecurityToken) != "" {
		return aliecs.NewClientWithStsToken(region, credentials.AccessKeyID, credentials.AccessKeySecret, credentials.SecurityToken)
	}
	return aliecs.NewClientWithAccessKey(region, credentials.AccessKeyID, credentials.AccessKeySecret)
}

func newVPCClient(region string, credentials Credentials) (*alivpc.Client, error) {
	if strings.TrimSpace(credentials.SecurityToken) != "" {
		return alivpc.NewClientWithStsToken(region, credentials.AccessKeyID, credentials.AccessKeySecret, credentials.SecurityToken)
	}
	return alivpc.NewClientWithAccessKey(region, credentials.AccessKeyID, credentials.AccessKeySecret)
}

type proxySetter interface {
	SetHttpProxy(string)
	SetHttpsProxy(string)
}

func setV1Proxy(client proxySetter, config map[string]string) {
	proxy := firstNonEmpty(config["proxy"], config["proxy_config"])
	if proxy == "" {
		return
	}
	client.SetHttpProxy(proxy)
	client.SetHttpsProxy(proxy)
}

func newSLBClient(region string, config *openapi.Config) (*slb20140515.Client, error) {
	config.Endpoint = tea.String("slb." + region + ".aliyuncs.com")
	client, err := slb20140515.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func newALBClient(region string, config *openapi.Config) (*alb20200616.Client, error) {
	config.Endpoint = tea.String("alb." + region + ".aliyuncs.com")
	client, err := alb20200616.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func newNLBClient(region string, config *openapi.Config) (*nlb20220430.Client, error) {
	config.Endpoint = tea.String("nlb." + region + ".aliyuncs.com")
	client, err := nlb20220430.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func newRAMClient(region string, config *openapi.Config) (*ram20150501.Client, error) {
	config.Endpoint = tea.String("ram.aliyuncs.com")
	client, err := ram20150501.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func newIMSClient(region string, config *openapi.Config) (*ims20190815.Client, error) {
	config.Endpoint = tea.String("ims.aliyuncs.com")
	client, err := ims20190815.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func newRDSClient(region string, config *openapi.Config) (*rds20140815.Client, error) {
	client, err := rds20140815.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func newDASClient(region string, config *openapi.Config) (*das20200116.Client, error) {
	config.Endpoint = tea.String("das." + region + ".aliyuncs.com")
	return das20200116.NewClient(config)
}

func newRedisClient(region string, config *openapi.Config) (*r_kvstore20150101.Client, error) {
	client, err := r_kvstore20150101.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func newMongoDBClient(region string, config *openapi.Config) (*dds20151201.Client, error) {
	client, err := dds20151201.NewClient(config)
	if client != nil {
		client.RegionId = tea.String(region)
	}
	return client, err
}

func specForResourceType(resourceType string) ResourceSpec {
	normalized := normalizeResourceType(resourceType)
	for _, spec := range AllResourceSpecs() {
		if normalizeResourceType(spec.Type) == normalized {
			return spec
		}
	}
	return ResourceSpec{Type: resourceType, Normalized: normalized, Dimension: DimensionRegional}
}

func ecsSecurityGroupRelationships(account liteprovider.Account, _ coreschema.Resource, region string, properties map[string]any) []liteprovider.Relationship {
	ids := recursiveStrings(properties, "SecurityGroupId")
	if len(ids) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	relationships := make([]liteprovider.Relationship, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		relationships = append(relationships, liteprovider.Relationship{
			Type:     "uses_security_group",
			TargetID: aliCloudAssetID(account.AccountID, region, "Security Group", id),
			Properties: map[string]any{
				"security_group_id": id,
			},
		})
	}
	return relationships
}

func recursiveStrings(value any, target string) []string {
	var values []string
	collectRecursiveStrings(value, target, &values)
	return values
}

func collectRecursiveStrings(value any, target string, values *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, value := range typed {
			if key == target {
				appendStringValues(value, values)
				continue
			}
			collectRecursiveStrings(value, target, values)
		}
	case []any:
		for _, item := range typed {
			collectRecursiveStrings(item, target, values)
		}
	}
}

func appendStringValues(value any, values *[]string) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			appendStringValues(item, values)
		}
	case []string:
		for _, item := range typed {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				*values = append(*values, trimmed)
			}
		}
	default:
		if stringValue := stringFromAny(value); stringValue != "" {
			*values = append(*values, stringValue)
		}
	}
}
