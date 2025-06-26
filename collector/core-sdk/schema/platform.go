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

// PlatformConfig
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
	verifyPlatformConfig(config)
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

func verifyPlatformConfig(config PlatformConfig) {
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

func (p *Platform) CollectorV3(param CollectorParam) (err error) {
	startTime := time.Now()
	defer func() {
		p.clearVersionMap()
		p.clearRegionServices()
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		log.GetWLogger().Info(fmt.Sprintf("Platform => [%s] Program run time: %v\n", p.Name, duration))
	}()

	// wait all account finish
	var accountWait sync.WaitGroup
	for _, cloudAccount := range param.accounts {
		accountWait.Add(1)
		s := time.Now()
		p.handleAccount(cloudAccount, param, &accountWait)
		endTime := time.Now()
		duration := endTime.Sub(s)

		log.GetWLogger().Info(fmt.Sprintf("Platform => [%s] CloudAccountId => [%s] Program run time: %v\n", p.Name, cloudAccount.CloudAccountId, duration))
	}
	accountWait.Wait()
	return
}

func (p *Platform) handleAccount(account CloudAccount, param CollectorParam, parentWg *sync.WaitGroup) {
	defer func() {
		// Clean up region services for this account
		p.regionServices.Range(func(key, value interface{}) bool {
			keyStr := key.(string)
			if strings.Contains(keyStr, account.CloudAccountId) {
				p.regionServices.Delete(key)
			}
			return true
		})
		parentWg.Done()
	}()

	// wait all resource finish
	var pullResourceWait sync.WaitGroup
	// wait all submit finish
	var submitWait sync.WaitGroup

	for _, resource := range p.Resources {
		time.Sleep(3 * time.Second)
		pullResourceWait.Add(1)
		go func(resource Resource) {
			p.handleResource(account, resource, param, &pullResourceWait, &submitWait)
		}(resource)
	}
	// wait all resource finish
	pullResourceWait.Wait()
	// wait all submit finish
	submitWait.Wait()
	// send account running finish signal
	if param.registered {
		log.GetWLogger().Info(fmt.Sprintf("Platform => [%s] account [%s] send running finish signal success", p.Name, account.CloudAccountId))
		e := p.client.SendRunningFinishSignal(account.CloudAccountId, account.TaskId)
		if e != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Platform => [%s] account [%s] send running finish signal err %s", p.Name, account.CloudAccountId, e))
		}
	}
}

func (p *Platform) handleResource(account CloudAccount, resource Resource, collectorParam CollectorParam, pullResourceWait *sync.WaitGroup, submitWait *sync.WaitGroup) {
	defer pullResourceWait.Done()
	if collectorParam.registered && len(account.ResourceTypeList) != 0 && !utils.Contains(account.ResourceTypeList, resource.ResourceType) {
		errorMsg := fmt.Sprintf("Code:[%s] Platform => [%s] ResourceType => [%s] will not be collected because the account [%s] is not configured", CollectorError, p.Name, resource.ResourceType, account.CloudAccountId)
		log.GetWLogger().Warn(errorMsg)
		collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errorMsg))
		return
	}

	loopRegions := p.getLoopRegion(account, resource)

	log.GetWLogger().Info(fmt.Sprintf("Running CloudAccountId => [%s] Platform => [%s] ResourceType => [%s]  LoopRegions => [%s]", account.CloudAccountId, p.Name, resource.ResourceType, loopRegions))

	resourceKey := account.Platform + resource.ResourceType + account.CloudAccountId
	version := p.generateUUIDWithVersion(resourceKey)
	log.GetWLogger().Info("version been created ==>", zap.String("resourceKey", resourceKey), zap.String("version", version))

	// loop regions
	loopRegionWait := &sync.WaitGroup{}
	for _, region := range loopRegions {
		param, _ := getCloudAccountParam(account, region, resource.ResourceType)
		// Get or create a region-specific service instance
		regionService := p.getRegionService(region, resource.ResourceType, account.CloudAccountId)
		err := regionService.InitServices(param)
		if err != nil {
			errorMsg := fmt.Sprintf("Code:[%s] Running CloudAccountId => [%s] Region => [%s] Platform => [%s] ResourceType => [%s] Init Client error", CollectorError, account.CloudAccountId, region, p.Name, resource.ResourceType)
			log.GetWLogger().Warn(errorMsg)
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
						log.GetWLogger().Error("json Unmarshal err", zap.Error(err))
					}
					// If the registration is not successful, it will be printed on the console.
					if !collectorParam.registered {
						if err := utils.PrettyPrintJSON(string(marshal)); err != nil {
							log.GetWLogger().Error(fmt.Sprintf("Failed to format JSON: %s", err))
						}
					}

					result, err := getJsonPathValue(d, resource.Dimension, resource.RowField, account.CloudAccountId)
					if err != nil {
						errorMsg := fmt.Sprintf("Code:[%s] %s The data will not be submitted to the server Platform => [%s] ResourceType => [%s]", CollectorError, err.Error(), p.Name, resource.ResourceType)
						log.GetWLogger().Warn(errorMsg)
						collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errorMsg))
						continue
					}

					resourceChan <- &result
				case <-time.After(constant.TimeOut * time.Second):
					close(resourceChan)
					close(regionCh)
					// Ensure that all resource been saved resourceChan
					time.Sleep(5 * time.Second)
				}
			}
		}()

		// Producer
		loopRegionWait.Add(1)
		ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
		// Get rate limiter for this region
		limiter := p.getRegionLimiter(region)
		// Acquire semaphore
		limiter <- struct{}{}
		ctx = context.WithValue(ctx, constant.CloudAccountId, account.CloudAccountId)
		ctx = context.WithValue(ctx, constant.RegionId, region)
		ctx = context.WithValue(ctx, constant.ResourceType, resource.ResourceType)
		ctx = context.WithValue(ctx, constant.TraceId, version)
		go func(ctx context.Context, regionService ServiceInterface) {
			defer func() {
				cancel()
				loopRegionWait.Done()
				// Release the semaphore
				<-limiter
				// Handle panic caused by timeout shutdown of chan
				if r := recover(); r != nil {
					errMsg := fmt.Sprintf("%v", r)
					if strings.Contains(errMsg, "send on closed channel") {
						log.GetWLogger().Warn(fmt.Sprintf("Timeout, more than %d seconds !!! CloudAccountId => [%s] Platform => [%s] Region => [%s]  ResourceType => [%s]", constant.TimeOut, account.CloudAccountId, p.Name, region, resource.ResourceType))
					} else {
						errmsg := fmt.Sprintf("Code:[%s], CloudAccountId => [%s] Platform => [%s] Region => [%s] ResourceType => [%s] Recovered from panic of unknown type: %s", UnknownError, account.CloudAccountId, p.Name, region, resource.ResourceType, r)
						log.GetWLogger().Error(errmsg)
						collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errMsg))
					}
				}
			}()

			if resource.ResourceDetailFunc != nil {
				if err = resource.ResourceDetailFunc(ctx, regionService, regionCh); err != nil {
					errmsg := fmt.Sprintf("Code:[%s], CloudAccountId => [%s] Platform => [%s] Region => [%s] ResourceType => [%s] ERROR \n %s", CollectorError, account.CloudAccountId, p.Name, region, resource.ResourceType, err.Error())
					log.GetWLogger().Info(errmsg)
					collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errmsg))
				}
			}

			if resource.ResourceDetailFuncWithCancel != nil {
				if err = resource.ResourceDetailFuncWithCancel(ctx, cancel, regionService, regionCh); err != nil {
					errmsg := fmt.Sprintf("Code:[%s], CloudAccountId => [%s] Platform => [%s] Region => [%s] ResourceType => [%s] ERROR \n %s", SDKError, account.CloudAccountId, p.Name, region, resource.ResourceType, err.Error())
					log.GetWLogger().Info(errmsg)
					collectorParam.CloudRecLogger.logAccountError(account.Platform, resource.ResourceType, account.CloudAccountId, account.CollectRecordId, errors.New(errmsg))
				}
				// Waiting timeout or Cancel
				<-ctx.Done()
			}

		}(ctx, regionService)

		if resource.Dimension == Global {
			break
		}

		time.Sleep(1 * time.Second)
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

// deleteUUIDVersion deletes a UUID version from the map for a given key.
func (p *Platform) deleteUUIDVersion(key string) {
	version, exist := p.getUUIDVersion(key)
	if exist {
		log.GetWLogger().Info("version will remove ==>", zap.String("key", key), zap.String("version", version))
		// Delete the key-value pair from the map
		p.uuidVersionMap.Delete(key)
	}
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
