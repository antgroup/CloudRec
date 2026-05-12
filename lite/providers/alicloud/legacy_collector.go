package alicloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/collectorstate"
	"github.com/antgroup/CloudRec/lite/internal/progress"
	"github.com/antgroup/CloudRec/lite/internal/provider"
	"github.com/cloudrec/alicloud/collector/cloudapi"
	"github.com/cloudrec/alicloud/collector/dbs"
	"github.com/cloudrec/alicloud/collector/mse"
	"github.com/cloudrec/alicloud/collector/ram"
	legacyplatform "github.com/cloudrec/alicloud/platform"
	coreconstant "github.com/core-sdk/constant"
	coreschema "github.com/core-sdk/schema"
	"github.com/yalp/jsonpath"
)

const defaultLegacyCollectorTimeout = 240 * time.Second

// LegacyCollector adapts the existing full Alibaba Cloud collector package into
// the lightweight provider contract. It lets lite reuse the current collector
// coverage while we incrementally replace hot paths with smaller native adapters.
type LegacyCollector struct {
	resources      []coreschema.Resource
	defaultRegions []string
	service        coreschema.ServiceInterface
	timeout        time.Duration
	concurrency    int
}

type LegacyCollectorOption func(*LegacyCollector)

func NewLegacyCollector(options ...LegacyCollectorOption) *LegacyCollector {
	platform := legacyplatform.GetPlatformConfig()
	collector := &LegacyCollector{
		resources:      legacyResources(platform.Resources),
		defaultRegions: append([]string(nil), platform.DefaultRegions...),
		service:        platform.Service,
		timeout:        defaultLegacyCollectorTimeout,
		concurrency:    defaultCollectorConcurrency,
	}
	for _, option := range options {
		option(collector)
	}
	return collector
}

func WithLegacyResources(resources []coreschema.Resource) LegacyCollectorOption {
	return func(collector *LegacyCollector) {
		collector.resources = append([]coreschema.Resource(nil), resources...)
	}
}

func WithLegacyDefaultRegions(regions []string) LegacyCollectorOption {
	return func(collector *LegacyCollector) {
		if len(regions) == 0 {
			return
		}
		collector.defaultRegions = append([]string(nil), regions...)
	}
}

func WithLegacyService(service coreschema.ServiceInterface) LegacyCollectorOption {
	return func(collector *LegacyCollector) {
		if service != nil {
			collector.service = service
		}
	}
}

func WithLegacyTimeout(timeout time.Duration) LegacyCollectorOption {
	return func(collector *LegacyCollector) {
		if timeout > 0 {
			collector.timeout = timeout
		}
	}
}

func WithLegacyConcurrency(concurrency int) LegacyCollectorOption {
	return func(collector *LegacyCollector) {
		if concurrency > 0 {
			collector.concurrency = concurrency
		}
	}
}

func (c *LegacyCollector) Collect(ctx context.Context, account provider.Account, credentials Credentials) ([]provider.Asset, error) {
	if c.service == nil {
		return nil, errors.New("alicloud legacy collector requires a service")
	}
	timeout, err := collectorTimeout(account.Config, c.timeout)
	if err != nil {
		return nil, err
	}
	concurrency, err := collectorConcurrency(account.Config, c.concurrency)
	if err != nil {
		return nil, err
	}

	resources := c.resourcesByType()
	specs := specsForAccount(account)
	if len(specs) == 0 {
		return nil, ErrSDKCollectionNotImplemented
	}

	var (
		assets   []provider.Asset
		missing  []string
		failures []provider.CollectionFailure
		work     []legacyCollectTask
	)
	tasks := make([]string, 0)
	for _, spec := range specs {
		resource, ok := resources[normalizeResourceType(spec.Type)]
		if !ok {
			continue
		}
		for _, region := range c.regionsForResource(account, credentials, resource) {
			work = append(work, legacyCollectTask{resource: resource, region: region})
			tasks = append(tasks, resourceRegionTask(resource.ResourceType, region))
		}
	}
	tracker := progress.FromContext(ctx).Tracker("alicloud legacy collector", tasks)
	tracker.Start()
	for _, spec := range specs {
		if _, ok := resources[normalizeResourceType(spec.Type)]; !ok {
			missing = append(missing, spec.Type)
		}
	}
	if len(work) > 0 {
		results := c.collectWork(ctx, account, credentials, work, timeout, concurrency, tracker)
		for _, result := range results {
			assets = append(assets, result.assets...)
			failures = append(failures, result.failures...)
		}
	}
	tracker.Finish("finished")

	if len(failures) > 0 {
		return assets, &provider.PartialCollectionError{
			Assets:   assets,
			Failures: failures,
		}
	}
	if len(assets) == 0 && len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrSDKCollectionNotImplemented, strings.Join(missing, ", "))
	}
	return assets, nil
}

type legacyCollectTask struct {
	resource coreschema.Resource
	region   string
}

type legacyCollectResult struct {
	assets   []provider.Asset
	failures []provider.CollectionFailure
}

func (c *LegacyCollector) collectWork(ctx context.Context, account provider.Account, credentials Credentials, work []legacyCollectTask, timeout time.Duration, concurrency int, tracker *progress.Tracker) []legacyCollectResult {
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(work) {
		concurrency = len(work)
	}

	workCh := make(chan legacyCollectTask)
	resultCh := make(chan legacyCollectResult, len(work))
	var wg sync.WaitGroup
	var trackerMu sync.Mutex
	taskStart := func(task string) {
		trackerMu.Lock()
		defer trackerMu.Unlock()
		tracker.TaskStart(task)
	}
	taskDone := func(task string, taskErr error, cost time.Duration) {
		trackerMu.Lock()
		defer trackerMu.Unlock()
		tracker.TaskDone(task, taskErr, cost)
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workCh {
				resultCh <- c.collectWorkItem(ctx, account, credentials, item, timeout, taskStart, taskDone)
			}
		}()
	}
	go func() {
		defer close(workCh)
		for _, item := range work {
			select {
			case <-ctx.Done():
				return
			case workCh <- item:
			}
		}
	}()
	wg.Wait()
	close(resultCh)

	results := make([]legacyCollectResult, 0, len(work))
	for result := range resultCh {
		results = append(results, result)
	}
	return results
}

func (c *LegacyCollector) collectWorkItem(ctx context.Context, account provider.Account, credentials Credentials, item legacyCollectTask, timeout time.Duration, taskStart func(string), taskDone func(string, error, time.Duration)) legacyCollectResult {
	task := resourceRegionTask(item.resource.ResourceType, item.region)
	taskStart(task)
	started := time.Now()

	if entry, ok := collectorstate.LookupSkip(ctx, item.resource.ResourceType, item.region); ok {
		span := collectorstate.StartTask(ctx, "alicloud legacy collector", item.resource.ResourceType, item.region)
		span.Skip(entry.Category, entry.Message)
		taskDone(task, nil, time.Since(started))
		return legacyCollectResult{}
	}

	span := collectorstate.StartTask(ctx, "alicloud legacy collector", item.resource.ResourceType, item.region)
	collected, err := c.collectResourceRegion(ctx, account, credentials, item.resource, item.region, timeout)
	if err != nil && len(collected) == 0 && retryableCollectionError(err) {
		if delay := retryDelay(1); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
				collected, err = c.collectResourceRegion(ctx, account, credentials, item.resource, item.region, timeout)
			}
		}
	}
	category, message := collectionErrorDetails(err)
	span.Done(err, category, message, len(collected))
	if err != nil {
		collectorstate.ObserveFailure(ctx, item.resource.ResourceType, item.region, category, message)
	}
	taskDone(task, err, time.Since(started))
	if err != nil {
		return legacyCollectResult{
			assets:   collected,
			failures: []provider.CollectionFailure{resourceFailure(item.resource.ResourceType, item.region, err)},
		}
	}
	return legacyCollectResult{assets: collected}
}

func (c *LegacyCollector) resourcesByType() map[string]coreschema.Resource {
	resources := make(map[string]coreschema.Resource, len(c.resources))
	for _, resource := range c.resources {
		if resource.ResourceType == "" {
			continue
		}
		resources[normalizeResourceType(resource.ResourceType)] = resource
	}
	return resources
}

func (c *LegacyCollector) regionsForResource(account provider.Account, credentials Credentials, resource coreschema.Resource) []string {
	if regions := explicitRegions(account); len(regions) > 0 {
		if resource.Dimension == coreschema.Global {
			regions = regions[:1]
		}
		return applyRegionMatrix(resource.ResourceType, regions, true)
	}

	if resource.Dimension == coreschema.Global {
		return applyRegionMatrix(resource.ResourceType, []string{firstNonEmpty(credentials.Region, firstString(resource.Regions), firstString(c.defaultRegions), "cn-hangzhou")}, false)
	}

	regions := resource.Regions
	if len(regions) == 0 {
		regions = c.defaultRegions
	}
	return applyRegionMatrix(resource.ResourceType, excludeRegions(regions, resource.ExcludedRegions), false)
}

func explicitRegions(account provider.Account) []string {
	if account.DefaultRegion != "" {
		return []string{account.DefaultRegion}
	}
	if values := splitCSV(account.Config["regions"]); len(values) > 0 {
		return values
	}
	if value := strings.TrimSpace(account.Config["region"]); value != "" {
		return []string{value}
	}
	return nil
}

func (c *LegacyCollector) collectResourceRegion(ctx context.Context, account provider.Account, credentials Credentials, resource coreschema.Resource, region string, timeout time.Duration) ([]provider.Asset, error) {
	service := c.service.Clone()
	param := legacyCloudAccountParam(account, credentials, resource.ResourceType, region)
	if err := service.InitServices(param); err != nil {
		return nil, err
	}

	regionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	regionCtx = context.WithValue(regionCtx, coreconstant.CloudAccountId, account.AccountID)
	regionCtx = context.WithValue(regionCtx, coreconstant.CloudAccountConfig, cloneStringConfig(account.Config))
	regionCtx = context.WithValue(regionCtx, coreconstant.RegionId, region)
	regionCtx = context.WithValue(regionCtx, coreconstant.ResourceType, resource.ResourceType)

	dataCh := make(chan any, 50)
	errCh := make(chan error, 1)
	go func() {
		defer close(dataCh)
		defer close(errCh)
		defer func() {
			if recovered := recover(); recovered != nil {
				errCh <- fmt.Errorf("legacy collector panic: %v", recovered)
			}
		}()

		if resource.ResourceDetailFunc != nil {
			errCh <- resource.ResourceDetailFunc(regionCtx, service, dataCh)
			return
		}
		if resource.ResourceDetailFuncWithCancel != nil {
			errCh <- resource.ResourceDetailFuncWithCancel(regionCtx, cancel, service, dataCh)
			return
		}
		errCh <- nil
	}()

	var assets []provider.Asset
	var collectErr error
	done := regionCtx.Done()
	for dataCh != nil || errCh != nil {
		select {
		case data, ok := <-dataCh:
			if !ok {
				dataCh = nil
				continue
			}
			asset, err := assetFromLegacyData(account, resource, region, data)
			if err != nil {
				return assets, err
			}
			assets = append(assets, asset)
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if err != nil && collectErr == nil {
				collectErr = err
			}
			errCh = nil
		case <-done:
			if errors.Is(regionCtx.Err(), context.DeadlineExceeded) {
				return assets, fmt.Errorf("legacy collector timeout after %s", timeout)
			}
			done = nil
		}
	}
	return assets, collectErr
}

func legacyCloudAccountParam(account provider.Account, credentials Credentials, resourceType string, region string) coreschema.CloudAccountParam {
	return coreschema.CloudAccountParam{
		CloudAccountId: account.AccountID,
		Platform:       string(coreconstant.AlibabaCloud),
		ResourceType:   resourceType,
		ProxyConfig:    firstNonEmpty(account.Config["proxy"], account.Config["proxy_config"]),
		CommonCloudAccountParam: coreschema.CommonCloudAccountAuthParam{
			AK:     credentials.AccessKeyID,
			SK:     credentials.AccessKeySecret,
			Region: region,
		},
	}
}

func assetFromLegacyData(account provider.Account, resource coreschema.Resource, collectionRegion string, raw any) (provider.Asset, error) {
	decoded, properties, err := legacyProperties(raw)
	if err != nil {
		return provider.Asset{}, err
	}

	rowID := legacyJSONPathString(decoded, resource.RowField.ResourceId)
	rowName := legacyJSONPathString(decoded, resource.RowField.ResourceName)
	resourceID := firstNonEmpty(rowID, inferResourceID(properties))
	if resourceID == "" && resource.Dimension == coreschema.Global {
		resourceID = account.AccountID
	}
	if resource.RowField.ResourceId == "" && resourceID == account.AccountID {
		resourceID = stableFixtureID(properties)
	}
	if resourceID == "" {
		return provider.Asset{}, fmt.Errorf("resource id is empty")
	}

	name := firstNonEmpty(rowName, inferResourceName(properties), resourceID)
	region := firstNonEmpty(inferRegion(properties), collectionRegion)
	if resource.Dimension == coreschema.Global && (region == "" || region == collectionRegion) {
		region = firstNonEmpty(inferRegion(properties), "global")
	}

	return provider.Asset{
		ID:         aliCloudAssetID(account.AccountID, region, resource.ResourceType, resourceID),
		Provider:   ProviderName,
		AccountID:  account.AccountID,
		Type:       resource.ResourceType,
		Name:       name,
		Region:     region,
		Tags:       inferTags(properties),
		Properties: properties,
	}, nil
}

func legacyProperties(raw any) (any, map[string]any, error) {
	content, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, nil, err
	}
	return decoded, mapFromRaw(decoded), nil
}

func legacyJSONPathString(data any, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	value, err := jsonpath.Read(data, path)
	if err != nil {
		return ""
	}
	return stringFromAny(value)
}

func legacyResources(platformResources []coreschema.Resource) []coreschema.Resource {
	resources := make([]coreschema.Resource, 0, len(platformResources)+2)
	seen := map[string]struct{}{}
	extras := []coreschema.Resource{
		cloudapi.GetCloudAPIResource(),
		dbs.GetDBSBackupPlanResource(),
		mse.GetMSEClusterResource(),
		ram.GetGroupResource(),
	}
	for _, resource := range append(platformResources, extras...) {
		key := normalizeResourceType(resource.ResourceType)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		resources = append(resources, resource)
	}
	return resources
}

func excludeRegions(regions []string, excluded []string) []string {
	excludedSet := map[string]struct{}{}
	for _, region := range excluded {
		excludedSet[region] = struct{}{}
	}

	filtered := make([]string, 0, len(regions))
	for _, region := range regions {
		if _, ok := excludedSet[region]; ok {
			continue
		}
		filtered = append(filtered, region)
	}
	return filtered
}

func firstString(values []string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
