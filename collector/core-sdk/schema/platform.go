// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package schema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/utils"
	"github.com/yalp/jsonpath"
	"go.uber.org/zap"
)

// PlatformConfig platform config param
type PlatformConfig struct {
	// (required == true) platform name
	Name string

	// Default account, no need to obtain from the server,You can pass in a test account here
	DefaultCloudAccounts []CloudAccount

	// (required == true) List of resources that need to be run
	Resources []Resource

	// (required == true) Default region list
	DefaultRegions []string

	// (required == true) Supported cloud services
	Service ServiceInterface

	// Maximum number of accounts running simultaneously,default is DefaultCloudAccountMaxConcurrent,can be configured,The maximum cannot exceed 8
	CloudAccountMaxConcurrent int
}

type Platform struct {
	PlatformConfig
	// CloudAccounts []CloudAccount

	// Client with persistent token
	client *Client

	// Store all services
	servicesMap map[string]ServiceInterface

	// key: platform+resource+cloudAccountId, value: UUID version
	uuidVersionMap sync.Map

	// key: region, value: ServiceInterface
	regionServices sync.Map

	// Rate limiter for each region
	regionLimiters sync.Map // key: region, value: chan struct{}

	// Maximum concurrent requests per region
	maxConcurrentRequests int
}

var instance *Platform

// GetInstance Created instance in singleton mode
func GetInstance(config PlatformConfig) *Platform {
	verifyPlatformConfig(&config)
	config.DefaultRegions = utils.UniqueList(config.DefaultRegions)
	instance = &Platform{
		PlatformConfig:        config,
		servicesMap:           make(map[string]ServiceInterface, 2*len(config.DefaultCloudAccounts)),
		maxConcurrentRequests: 10, // 默认每个区域最多10个并发请求
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	return instance
}

// RunExecutors Merge multiple platforms to run in the same process
func RunExecutors(params ...*Platform) {
	var wg sync.WaitGroup
	errCh := make(chan error, len(params))

	for _, param := range params {
		wg.Add(1)
		go func(p *Platform) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errCh <- fmt.Errorf("panic occurred: %v", r)
				}
			}()
			if err := RunExecutor(p); err != nil {
				log.GetWLogger().Error(err.Error())
				errCh <- err
			}
		}(param)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		log.GetWLogger().Error(err.Error())
	}
}

func verifyPlatformConfig(config *PlatformConfig) {
	if config.Name == "" {
		panic(errors.New("platform name is empty"))
	}
	if config.Service == nil {
		panic(errors.New("platform service is nil"))
	}
	if len(config.Resources) == 0 {
		panic(errors.New("platform resources is empty"))
	}
	if len(config.DefaultRegions) == 0 {
		panic(errors.New("platform default regions is empty"))
	}
	if config.CloudAccountMaxConcurrent == 0 {
		config.CloudAccountMaxConcurrent = constant.DefaultCloudAccountMaxConcurrent
	}
	if config.CloudAccountMaxConcurrent > 8 || config.CloudAccountMaxConcurrent < 1 {
		log.GetWLogger().Info("The configured CloudAccountMaxConcurrent exceeds 8 or less than 1, and the default value will be used.", zap.Int("CloudAccountMaxConcurrent", config.CloudAccountMaxConcurrent))
		config.CloudAccountMaxConcurrent = constant.DefaultCloudAccountMaxConcurrent
	}
}

type CollectorParam struct {
	registered     bool
	task           interface{}
	accounts       []CloudAccount
	CloudRecLogger *CloudRecLogger
}

// CollectorV3 collect resource v3
// clearRegionServices cleans up region-specific service instances
// Get or create rate limiter for the region
func (p *Platform) getRegionLimiter(region string) chan struct{} {
	limiter, ok := p.regionLimiters.Load(region)
	if !ok {
		limiter = make(chan struct{}, p.maxConcurrentRequests)
		p.regionLimiters.Store(region, limiter)
	}
	return limiter.(chan struct{})
}

func (p *Platform) clearRegionServices() {
	p.regionServices.Range(func(key, value interface{}) bool {
		p.regionServices.Delete(key)
		return true
	})
}

// CollectorV3 collect resource v3
// Simplified version for queue-based processing - accounts are processed sequentially
// since AccountQueue already handles concurrency control at the system level
func (p *Platform) CollectorV3(param CollectorParam) (err error) {
	startTime := time.Now()
	defer func() {
		p.clearVersionMap()
		p.clearRegionServices()
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		log.GetWLogger().Info(fmt.Sprintf("Platform => [%s] Program run time: %v\n", p.Name, duration))
	}()

	// Process accounts sequentially since queue mechanism handles concurrency
	for _, cloudAccount := range param.accounts {
		s := time.Now()
		// Create context with cloud account information
		ctx := context.Background()
		ctx = context.WithValue(ctx, constant.StartTime, time.Now())
		ctx = context.WithValue(ctx, constant.Platform, p.Name)
		ctx = context.WithValue(ctx, constant.CloudAccountId, cloudAccount.CloudAccountId)
		ctx = context.WithValue(ctx, constant.CollectRecordId, cloudAccount.CollectRecordId)

		p.handleAccount(ctx, cloudAccount, param)

		endTime := time.Now()
		duration := endTime.Sub(s)
		log.CtxLogger(ctx).Info(fmt.Sprintf("Program run time: %v", duration))
	}
	return
}

// handleAccount processes a cloud account with context containing account information
// ctx: context containing Platform, CloudAccountId, and CollectRecordId
// account: cloud account information to be processed
// param: collector parameters including logger and registration status
func (p *Platform) handleAccount(ctx context.Context, account CloudAccount, param CollectorParam) {
	// Record start time for duration calculation
	startTime := time.Now()
	// Log cloud account collection start
	log.CtxLogger(context.WithValue(ctx, constant.StartTime, startTime)).Info("Started collecting cloud account")

	defer func() {
		// Calculate duration and log cloud account collection end
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		logCtx := context.WithValue(ctx, constant.EndTime, endTime)
		logCtx = context.WithValue(logCtx, constant.Duration, duration)
		log.CtxLogger(logCtx).Info(fmt.Sprintf("Completed collecting cloud account, Duration=[%v]", duration))
		// Clean up region services for this account
		p.regionServices.Range(func(key, value interface{}) bool {
			keyStr := key.(string)
			if strings.Contains(keyStr, account.CloudAccountId) {
				p.regionServices.Delete(key)
			}
			return true
		})
	}()

	accountParam, err := getCloudAccountParam(account, p.DefaultRegions[0], "")
	if err != nil {
		log.CtxLogger(ctx).Warn(fmt.Sprintf("Failed to get cloud account param for AssessCollectionTrigger check: %v", err))
		return
	}

	if param.registered && !p.assessCollectionChecker(ctx, accountParam) {
		log.CtxLogger(ctx).Info("Skipping collection - AssessCollectionTrigger returned false")
		e := p.client.SendRunningFinishSignal(account.CloudAccountId, account.TaskId)
		if e != nil {
			log.CtxLogger(ctx).Warn(fmt.Sprintf("Code:[%s] SendRunningFinishSignal error %s", CollectorError, e))
		}
		return
	}

	// wait all resource finish
	var pullResourceWait sync.WaitGroup
	// wait all submit finish
	var submitWait sync.WaitGroup

	for _, resource := range p.Resources {
		time.Sleep(1 * time.Second)
		pullResourceWait.Add(1)
		go func(resource Resource) {
			// Add resource-specific information to the existing context
			resourceCtx := context.WithValue(ctx, constant.ResourceType, resource.ResourceType)
			p.handleResource(resourceCtx, account, resource, param, &pullResourceWait, &submitWait)
		}(resource)
	}
	// wait all resource finish
	pullResourceWait.Wait()
	// wait all submit finish
	submitWait.Wait()
	// send account running finish signal
	if param.registered {
		log.CtxLogger(ctx).Info("Send running finish signal success")
		e := p.client.SendRunningFinishSignal(account.CloudAccountId, account.TaskId)
		if e != nil {
			log.CtxLogger(ctx).Warn(fmt.Sprintf("Code:[%s] SendRunningFinishSignal err %s", CollectorError, e))
		}
	}
}

func (p *Platform) assessCollectionChecker(ctx context.Context, accountParam CloudAccountParam) bool {
	tempService := p.Service.Clone()
	// Check if collection should be performed for this account
	resp := tempService.AssessCollectionTrigger(accountParam)
	if !resp.EnableCollection {
		log.CtxLogger(ctx).Info("Skipping collection - AssessCollectionTrigger returned false")
	}

	resp.CollectRecordId = accountParam.CollectRecordInfo.CollectRecordId
	err := p.client.SendRunningStartSignal(resp)
	if err != nil {
		log.CtxLogger(ctx).Warn(fmt.Sprintf("Code:[%s] SendRunningStartSignal err %s", CollectorError, err))
		return false
	}
	return resp.EnableCollection
}

// handleResource processes a specific resource for a cloud account with context containing account information
// ctx: context containing CloudAccountId, Platform, ResourceType, and CollectRecordId
// account: cloud account information
// resource: resource configuration to be collected
// collectorParam: collector parameters including logger and registration status
// pullResourceWait: wait group for resource pulling operations
// submitWait: wait group for resource submission operations
func (p *Platform) handleResource(ctx context.Context, account CloudAccount, resource Resource, collectorParam CollectorParam, pullResourceWait *sync.WaitGroup, submitWait *sync.WaitGroup) {
	// Record start time for duration calculation
	startTime := time.Now()
	// Log resource collection start
	log.CtxLogger(context.WithValue(ctx, constant.StartTime, startTime)).Info("Started collecting resource")

	defer func() {
		// Calculate duration and log resource collection end
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		logCtx := context.WithValue(ctx, constant.EndTime, endTime)
		logCtx = context.WithValue(logCtx, constant.Duration, duration)
		log.CtxLogger(logCtx).Info(fmt.Sprintf("Completed collecting resource, Duration=[%v]", duration))
		pullResourceWait.Done()
	}()
	if collectorParam.registered && len(account.ResourceTypeList) != 0 && !utils.Contains(account.ResourceTypeList, resource.ResourceType) {
		errorMsg := fmt.Sprintf("Code:[%s] ResourceType will not be collected because the account is not configured", CollectorError)
		log.CtxLogger(ctx).Warn(errorMsg)
		collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errorMsg))
		return
	}

	loopRegions := p.getLoopRegion(account, resource)
	resourceKey := account.Platform + resource.ResourceType + account.CloudAccountId
	version := p.generateUUIDWithVersion(resourceKey)

	// loop regions
	loopRegionWait := &sync.WaitGroup{}
	for _, region := range loopRegions {
		param, _ := getCloudAccountParam(account, region, resource.ResourceType)
		// Get or create a region-specific service instance
		regionService := p.getRegionService(region, resource.ResourceType, account.CloudAccountId)
		err := regionService.InitServices(param)
		if err != nil {
			errorMsg := fmt.Sprintf("Code:[%s] Init Client error %v", CollectorError, err)
			log.CtxLogger(ctx).Warn(errorMsg)
			collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errorMsg))
			continue
		}

		// Open the chan that receives resource data
		resourceChan := make(chan *ResourceInstance, constant.DefaultPageSize)
		submitWait.Add(1)
		go Submit(p.client, account, resource, resourceChan, collectorParam.registered, version, submitWait)

		// for region chan
		regionCh := make(chan interface{}, constant.DefaultPageSize)

		// Consumer
		go func() {
			for {
				select {
				case data, ok := <-regionCh:
					if !ok {
						return
					}
					marshal, _ := json.Marshal(data)
					var d interface{}
					err := json.Unmarshal(marshal, &d)
					if err != nil {
						log.CtxLogger(ctx).Error("json Unmarshal err", zap.Error(err))
					}
					// If the registration is not successful, it will be printed on the console.
					if !collectorParam.registered {
						if err := utils.PrettyPrintJSON(string(marshal)); err != nil {
							log.CtxLogger(ctx).Error(fmt.Sprintf("Failed to format JSON: %s", err))
						}
					}

					result, err := getJsonPathValue(d, resource.Dimension, resource.RowField, account.CloudAccountId)
					if err != nil {
						errorMsg := fmt.Sprintf("Code:[%s] %s  The data will not be submitted to the server", CollectorError, err.Error())
						log.CtxLogger(ctx).Warn(errorMsg)
						collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errorMsg))
						continue
					}

					resourceChan <- &result
				case <-time.After(constant.TimeOut * time.Second):
					close(resourceChan)
					close(regionCh)
					// Ensure that all resource been saved resourceChan
					// time.Sleep(5 * time.Second)
				}
			}
		}()

		// Producer
		loopRegionWait.Add(1)
		// Create timeout context based on the input context to preserve account information
		regionCtx, cancel := context.WithTimeout(ctx, 240*time.Second)
		// Get rate limiter for this region
		limiter := p.getRegionLimiter(region)
		// Acquire semaphore
		limiter <- struct{}{}
		// Add region-specific information to the context
		regionCtx = context.WithValue(regionCtx, constant.RegionId, region)
		regionCtx = context.WithValue(regionCtx, constant.TraceId, version)
		go func(regionCtx context.Context, regionService ServiceInterface) {
			defer func() {
				cancel()
				loopRegionWait.Done()
				// Release the semaphore
				<-limiter
				// Handle panic caused by timeout shutdown of chan
				if r := recover(); r != nil {
					errMsg := fmt.Sprintf("%v", r)
					if strings.Contains(errMsg, "send on closed channel") {
						log.CtxLogger(ctx).Warn(fmt.Sprintf("Timeout, more than %d seconds !!!", constant.TimeOut))
					} else {
						errmsg := fmt.Sprintf("Code:[%s] Recovered from panic of unknown type: %s", UnknownError, r)
						log.CtxLogger(ctx).Error(errmsg)
						collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errMsg))
					}
				}
				log.CtxLogger(context.WithValue(regionCtx, constant.EndTime, time.Now())).Info("LoopRegionWait Done")
			}()

			if resource.ResourceDetailFunc != nil {
				if err = resource.ResourceDetailFunc(regionCtx, regionService, regionCh); err != nil {
					errmsg := fmt.Sprintf("Code:[%s] ResourceDetailFunc ERROR: %s", CollectorError, err.Error())
					log.CtxLogger(ctx).Warn(errmsg)
					collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errmsg))
				}
			}

			if resource.ResourceDetailFuncWithCancel != nil {
				if err = resource.ResourceDetailFuncWithCancel(regionCtx, cancel, regionService, regionCh); err != nil {
					errmsg := fmt.Sprintf("Code:[%s] ResourceDetailFuncWithCancel ERROR: %s", SDKError, err.Error())
					log.CtxLogger(ctx).Warn(errmsg)
					collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errmsg))
				}
				// Waiting timeout or Cancel
				<-regionCtx.Done()
			}

		}(regionCtx, regionService)

		if resource.Dimension == Global {
			log.CtxLogger(ctx).Info("Global resource, no need to loop region")
			break
		}

		// time.Sleep(1 * time.Second)
	}
	loopRegionWait.Wait()
}

// Get the list of regions that need to be loop
func (p *Platform) getLoopRegion(account CloudAccount, resource Resource) (loopRegions []string) {
	if len(resource.Regions) == 0 {
		loopRegions = p.DefaultRegions
	} else {
		loopRegions = resource.Regions
	}

	loopRegions = utils.Exclude(loopRegions, resource.ExcludedRegions)

	// Alibaba Cloud Private Cloud needs to pass in regionId from the server
	if account.AliCloudPrivateCloudAccountAuthParam.Region != "" {
		var regions []string
		regions = append(regions, account.AliCloudPrivateCloudAccountAuthParam.Region)
		return regions
	}

	//Huawei Cloud Private Cloud needs to pass regionId from the server
	if account.HwsPrivateCloudAccountAuthParam.Region != "" {
		var regions []string
		regions = append(regions, account.HwsPrivateCloudAccountAuthParam.Region)
		return regions
	}

	return
}

func getJsonPathValue(d interface{}, dimension Dimension, rowField RowField, cloudAccountId string) (result ResourceInstance, err error) {
	builder := NewResourceBuilder()

	resourceId, err := jsonpath.Read(d, rowField.ResourceId)
	if resourceId == nil && dimension == Global {
		resourceId = cloudAccountId
	}
	builder.SetResourceId(resourceId)

	resourceName, err := jsonpath.Read(d, rowField.ResourceName)
	if resourceName == nil && dimension == Global {
		resourceName = cloudAccountId
	}
	builder.SetResourceName(resourceName)

	address, _ := jsonpath.Read(d, rowField.Address)
	builder.SetAddress(address)

	result, err = builder.SetInstance(d).Build()

	return result, err
}

// generates and stores a UUID version for a given key.
func (p *Platform) generateUUIDWithVersion(key string) string {
	version, exist := p.getUUIDVersion(key)
	if exist {
		return version
	}
	now := time.Now()
	// Format the time to a specific layout
	// Example: "20060102150405" translates to "YYYYMMDDHHMMSS"
	version = now.Format("20060102150405")
	return version
}

// getUUIDVersion retrieves the UUID version for a given key.
// Returns the version if found, or an empty string if not found.
func (p *Platform) getUUIDVersion(key string) (string, bool) {

	// Retrieve the UUID version from the map
	value, ok := p.uuidVersionMap.Load(key)
	if !ok {
		return "", false
	}
	return value.(string), true
}

// ClearVersionMap clears all entries from the global map.
func (p *Platform) clearVersionMap() {
	// Using a range loop to clear the map
	p.uuidVersionMap.Range(func(key, value interface{}) bool {
		p.uuidVersionMap.Delete(key)
		return true
	})
}

// getRegionService returns a region-specific service instance
func (p *Platform) getRegionService(region string, resourceType string, accountId string) ServiceInterface {
	key := fmt.Sprintf("%s-%s-%s", region, resourceType, accountId)
	if service, ok := p.regionServices.Load(key); ok {
		return service.(ServiceInterface)
	}

	// Create a new service instance for this region and resource type
	newService := p.Service.Clone()
	p.regionServices.Store(key, newService)
	return newService
}
