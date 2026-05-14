package alicloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/collectorstate"
	"github.com/antgroup/CloudRec/lite/internal/progress"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

var ErrResourceAdapterNotImplemented = errors.New("alicloud resource adapter is not implemented")

type AdapterRequest struct {
	Account     liteprovider.Account
	Credentials Credentials
	Spec        ResourceSpec
	Regions     []string
	Timeout     time.Duration
}

type ResourceAdapter interface {
	Spec() ResourceSpec
	Collect(context.Context, AdapterRequest) ([]liteprovider.Asset, error)
}

type RegistryCollector struct {
	adapters    map[string]ResourceAdapter
	regions     []string
	timeout     time.Duration
	concurrency int
}

type RegistryOption func(*RegistryCollector)

func NewRegistryCollector(options ...RegistryOption) *RegistryCollector {
	collector := &RegistryCollector{
		adapters: map[string]ResourceAdapter{},
		regions: []string{
			"cn-hangzhou",
			"cn-beijing",
			"cn-shanghai",
			"cn-shenzhen",
		},
		timeout:     30 * time.Second,
		concurrency: defaultCollectorConcurrency,
	}
	for _, option := range options {
		option(collector)
	}
	return collector
}

func WithRegistryConcurrency(concurrency int) RegistryOption {
	return func(collector *RegistryCollector) {
		if concurrency > 0 {
			collector.concurrency = concurrency
		}
	}
}

func WithResourceAdapter(adapter ResourceAdapter) RegistryOption {
	return func(collector *RegistryCollector) {
		if adapter == nil {
			return
		}
		collector.Register(adapter)
	}
}

func WithDefaultRegions(regions []string) RegistryOption {
	return func(collector *RegistryCollector) {
		if len(regions) == 0 {
			return
		}
		collector.regions = append([]string(nil), regions...)
	}
}

func (c *RegistryCollector) HasAdapter(resourceType string) bool {
	if c == nil {
		return false
	}
	_, ok := c.adapters[normalizeResourceType(resourceType)]
	return ok
}

func (c *RegistryCollector) Register(adapter ResourceAdapter) {
	if adapter == nil {
		return
	}
	spec := adapter.Spec()
	c.adapters[normalizeResourceType(spec.Type)] = adapter
}

func (c *RegistryCollector) Collect(ctx context.Context, account liteprovider.Account, credentials Credentials) ([]liteprovider.Asset, error) {
	timeout, err := collectorTimeout(account.Config, c.timeout)
	if err != nil {
		return nil, err
	}
	concurrency, err := collectorConcurrency(account.Config, c.concurrency)
	if err != nil {
		return nil, err
	}

	specs := specsForAccount(account)
	if len(specs) == 0 {
		return nil, ErrSDKCollectionNotImplemented
	}

	var (
		assets        []liteprovider.Asset
		unimplemented []string
		failures      []liteprovider.CollectionFailure
		work          []registryCollectTask
		tasks         []string
	)
	for _, spec := range specs {
		adapter, ok := c.adapters[normalizeResourceType(spec.Type)]
		if !ok {
			unimplemented = append(unimplemented, spec.Type)
			continue
		}

		for _, region := range c.regionsForSpec(account, spec) {
			work = append(work, registryCollectTask{
				spec:    spec,
				adapter: adapter,
				region:  region,
			})
			tasks = append(tasks, resourceRegionTask(spec.Type, region))
		}
	}

	tracker := progress.FromContext(ctx).Tracker("alicloud native collector", tasks)
	tracker.Start()
	if len(work) > 0 {
		results := c.collectWork(ctx, account, credentials, work, timeout, concurrency, tracker)
		for _, result := range results {
			assets = append(assets, result.assets...)
			failures = append(failures, result.failures...)
		}
	}
	tracker.Finish("finished")

	if len(failures) > 0 {
		return assets, &liteprovider.PartialCollectionError{
			Assets:   assets,
			Failures: failures,
		}
	}
	if len(assets) == 0 && len(unimplemented) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrSDKCollectionNotImplemented, strings.Join(unimplemented, ", "))
	}
	return assets, nil
}

type registryCollectTask struct {
	spec    ResourceSpec
	adapter ResourceAdapter
	region  string
}

type registryCollectResult struct {
	assets   []liteprovider.Asset
	failures []liteprovider.CollectionFailure
}

func (c *RegistryCollector) collectWork(ctx context.Context, account liteprovider.Account, credentials Credentials, work []registryCollectTask, timeout time.Duration, concurrency int, tracker *progress.Tracker) []registryCollectResult {
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(work) {
		concurrency = len(work)
	}

	workCh := make(chan registryCollectTask)
	resultCh := make(chan registryCollectResult, len(work))
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

	results := make([]registryCollectResult, 0, len(work))
	for result := range resultCh {
		results = append(results, result)
	}
	return results
}

func (c *RegistryCollector) collectWorkItem(ctx context.Context, account liteprovider.Account, credentials Credentials, item registryCollectTask, timeout time.Duration, taskStart func(string), taskDone func(string, error, time.Duration)) registryCollectResult {
	task := resourceRegionTask(item.spec.Type, item.region)
	taskStart(task)
	started := time.Now()

	if entry, ok := collectorstate.LookupSkip(ctx, item.spec.Type, item.region); ok {
		span := collectorstate.StartTask(ctx, "alicloud native collector", item.spec.Type, item.region)
		span.Skip(entry.Category, entry.Message)
		taskDone(task, nil, time.Since(started))
		return registryCollectResult{}
	}

	span := collectorstate.StartTask(ctx, "alicloud native collector", item.spec.Type, item.region)
	request := AdapterRequest{
		Account:     account,
		Credentials: credentials,
		Spec:        item.spec,
		Regions:     []string{item.region},
		Timeout:     timeout,
	}
	collected, err := item.adapter.Collect(ctx, request)
	if err != nil && len(collected) == 0 && retryableCollectionError(err) {
		if delay := retryDelay(1); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
				collected, err = item.adapter.Collect(ctx, request)
			}
		}
	}
	category, message := collectionErrorDetails(err)
	if partial, ok := asPartialCollectionError(err); ok && len(partial.Failures) > 0 {
		category = firstNonEmpty(partial.Failures[0].Category, category)
		message = firstNonEmpty(partial.Failures[0].Message, message)
	}
	span.Done(err, category, message, len(collected))
	if err != nil {
		if partial, ok := asPartialCollectionError(err); ok {
			for _, failure := range partial.Failures {
				collectorstate.ObserveFailure(ctx, firstNonEmpty(failure.ResourceType, item.spec.Type), firstNonEmpty(failure.Region, item.region), failure.Category, failure.Message)
			}
		} else {
			collectorstate.ObserveFailure(ctx, item.spec.Type, item.region, category, message)
		}
	}
	taskDone(task, err, time.Since(started))

	if err != nil {
		if partial, ok := asPartialCollectionError(err); ok {
			if len(collected) == 0 {
				collected = partial.Assets
			}
			return registryCollectResult{assets: collected, failures: partial.Failures}
		}
		return registryCollectResult{
			assets:   collected,
			failures: []liteprovider.CollectionFailure{resourceFailure(item.spec.Type, strings.Join(request.Regions, ","), err)},
		}
	}
	return registryCollectResult{assets: collected}
}

func (c *RegistryCollector) regionsForSpec(account liteprovider.Account, spec ResourceSpec) []string {
	if spec.Dimension == DimensionGlobal {
		return []string{"global"}
	}
	if regions := explicitRegions(account); len(regions) > 0 {
		return applyRegionMatrix(spec.Type, regions, true)
	}
	return applyRegionMatrix(spec.Type, append([]string(nil), c.regions...), false)
}

func specsForAccount(account liteprovider.Account) []ResourceSpec {
	selected := splitCSV(account.Config["resource_types"])
	if len(selected) == 0 {
		selected = splitCSV(account.Config["resources"])
	}
	if len(selected) == 0 {
		return AllResourceSpecs()
	}

	selectedSet := map[string]struct{}{}
	for _, value := range selected {
		selectedSet[normalizeResourceType(value)] = struct{}{}
	}

	var specs []ResourceSpec
	for _, spec := range AllResourceSpecs() {
		if _, ok := selectedSet[normalizeResourceType(spec.Type)]; ok {
			specs = append(specs, spec)
		}
	}
	return specs
}

func splitCSV(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		values = append(values, item)
	}
	return values
}
