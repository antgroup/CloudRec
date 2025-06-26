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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
)

// ResourceInstance resource instance
type ResourceInstance struct {
	ResourceName interface{} `json:"resourceName,omitempty"`

	ResourceId interface{} `json:"resourceId,omitempty"`

	Address interface{} `json:"address,omitempty"`

	RegionId string `json:"regionId,omitempty"`

	InChina bool `json:"inChina,omitempty"`

	TagList []*string `json:"tagList,omitempty"`

	Instance *interface{} `json:"instance,omitempty"`
}

// Builder set builder interface
type Builder interface {
	SetResourceId(resourceId string) *ResourceBuilder
	SetResourceName(resourceName string) *ResourceBuilder
	SetResourceType(resourceType string) *ResourceBuilder
	SetAddress(address string) *ResourceBuilder
	SetResourceGroupType(address string) *ResourceBuilder
	SetInstance(instance interface{}) *ResourceBuilder
	SetInChina(isAp bool) *ResourceBuilder
	GetError() error
	Build() (p ResourceInstance, e error)
}

// ResourceBuilder resource builder
type ResourceBuilder struct {
	ResourceInstance ResourceInstance
	err              error
}

// SetResourceId set ResourceId
func (r *ResourceBuilder) SetResourceId(resourceId interface{}) *ResourceBuilder {
	r.ResourceInstance.ResourceId = resourceId
	return r
}

// SetResourceName set ResourceName
func (r *ResourceBuilder) SetResourceName(resourceName interface{}) *ResourceBuilder {
	r.ResourceInstance.ResourceName = resourceName
	return r
}

// SetAddress set Address
func (r *ResourceBuilder) SetAddress(address interface{}) *ResourceBuilder {
	r.ResourceInstance.Address = address
	return r
}

// SetTagList set tag list
func (r *ResourceBuilder) SetTagList(tagList []*string) *ResourceBuilder {
	if tagList == nil || len(tagList) == 0 {
		r.err = errors.New("tagList is empty")
		return r
	}
	r.ResourceInstance.TagList = tagList
	return r
}

func (r *ResourceBuilder) SetTagList2(tagList []string) *ResourceBuilder {
	if tagList == nil || len(tagList) == 0 {
		r.err = errors.New("tagList is empty")
		return r
	}

	var tags []*string
	for _, v := range tagList {
		tags = append(tags, &v)
	}
	r.ResourceInstance.TagList = tags
	return r
}

// SetInstance set instance
func (r *ResourceBuilder) SetInstance(instance interface{}) *ResourceBuilder {
	r.ResourceInstance.Instance = &instance
	return r
}

// SetRegionId set RegionId
func (r *ResourceBuilder) SetRegionId(regionId string) *ResourceBuilder {
	r.ResourceInstance.RegionId = regionId
	return r
}

// SetInChina set isAp
func (r *ResourceBuilder) SetInChina(InChina bool) *ResourceBuilder {
	r.ResourceInstance.InChina = InChina
	return r
}

func (r *ResourceBuilder) Build() (p ResourceInstance, err error) {
	p = r.ResourceInstance
	if p.ResourceId == "" || p.ResourceId == nil {
		r.err = errors.New("resourceId is empty")
	}

	if p.Instance == nil {
		r.err = errors.New("instance is empty")
	}

	return p, r.GetError()
}

func (r *ResourceBuilder) GetError() error {
	return r.err
}

func NewResourceBuilder() *ResourceBuilder {
	return &ResourceBuilder{
		ResourceInstance: ResourceInstance{},
	}
}

type Dimension int

const (
	Global Dimension = iota
	Regional
)

// Resource struct defines a type of resource.
// Resource todo Need to detect parameters
type Resource struct {

	//
	ResourceType string

	//
	ResourceTypeName string

	// One of potential group a Resource can undergo:
	// - NET
	// - CONTAINER
	// - DATABASE
	// - STORE
	// - COMPUTE
	// - IDENTITY
	// - SECURITY
	// detail in core-sdk/constant/resource_group_type.go
	ResourceGroupType string

	// The description about Resource
	Desc string

	// ResourceDetailFunc is the main function invoked to fetch resource details
	ResourceDetailFunc ResourceDetailFunc

	// ResourceDetailFuncWithCancel
	ResourceDetailFuncWithCancel ResourceDetailFuncWithCancel

	// The field name of the row displayed on the web side.
	// You can specify the RowField field value from ResourceDetail by using jsonPath.
	// ResourceDetail is what ResourceDetailFunc fetches.
	RowField RowField

	// One of potential regional dimension a Resource can undergo:
	// Regional -
	// Global -
	Dimension Dimension

	// Not required, but if configured, it takes precedence over defaultRegion
	Regions []string

	// Excluded regions, if configured, it will be excluded from the region list
	ExcludedRegions []string
}

type RowField struct {

	// ResourceId is the unique key of a resource
	//
	// This member is required.
	// If you don't specify a ResourceId, account ID will be instead
	ResourceId string

	// ResourceName will be displayed at website
	ResourceName string

	// Public IP Address recommended
	Address string
}

type ResourceDetailFunc func(ctx context.Context, service ServiceInterface, res chan<- any) error
type ResourceDetailFuncWithCancel func(ctx context.Context, cancel context.CancelFunc, service ServiceInterface, res chan<- any) error

// Submit batch submit resource to server
func Submit(client *Client, account CloudAccount, resource Resource, res chan *ResourceInstance, registered bool, version string, submitWait *sync.WaitGroup) {
	if submitWait != nil {
		defer func() {
			if r := recover(); r != nil {
				log.GetWLogger().Error(fmt.Sprintf("Panic recovered in Submit function: %v", r))
			}
			submitWait.Done()
		}()
	}

	if !registered {
		for ret := range res {
			log.GetWLogger().Info(fmt.Sprintf("resourceId %s resourceName %s address %s", ret.ResourceId, ret.ResourceName, ret.Address))
		}
		return
	}

	var resourceInstances []*ResourceInstance

	sendResourceBatch := func() {
		if len(resourceInstances) == 0 {
			return
		}
		for i := 0; i < len(resourceInstances); i += constant.MaxResourcePushCount {
			end := i + constant.MaxResourcePushCount
			if end > len(resourceInstances) {
				end = len(resourceInstances)
			}

			const maxRetries = 3
			var err error
			for retry := 0; retry < maxRetries; retry++ {
				err = client.SendResource(account, resource, resourceInstances[i:end], version)
				if err == nil {
					break
				}

				log.GetWLogger().Warn(fmt.Sprintf("Failed to send resource batch (retry %d/%d): %s", retry+1, maxRetries, err.Error()))
				if retry < maxRetries-1 {
					time.Sleep(time.Duration(retry+1) * time.Second)
				}
			}

			if err != nil {
				log.GetWLogger().Error(fmt.Sprintf("Failed to send resource batch after %d retries: %s", maxRetries, err.Error()))
			}
		}
		resourceInstances = resourceInstances[:0]
	}

	for ret := range res {
		resourceInstances = append(resourceInstances, ret)
		if len(resourceInstances) >= constant.MaxResourcePushCount {
			sendResourceBatch()
		}
	}

	sendResourceBatch()
}
