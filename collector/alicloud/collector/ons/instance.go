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

package ons

import (
	"context"
	"sync"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ons"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const maxWorkers = 10

// GetInstanceResource returns ONS Instance resource definition
func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ONS_INSTANCE,
		ResourceTypeName:   "ONS Instance",
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               "https://help.aliyun.com/document_detail/29589.html",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
			Address:      "$.Instance.InstanceId",
		},
		Dimension: schema.Regional,
	}
}

// InstanceDetail aggregates resource details
type InstanceDetail struct {
	Instance         ons.InstanceVO
	InstanceBaseInfo ons.InstanceBaseInfo
}

// GetInstanceDetail gets ONS Instance details
func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Ons

	resources, err := listInstances(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list instances", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan ons.InstanceVO, len(resources))

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for resource := range tasks {
				detail := describeInstanceDetail(ctx, client, resource)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	for _, resource := range resources {
		tasks <- resource
	}
	close(tasks)

	wg.Wait()
	return nil
}

// listInstances gets a list of ONS Instances
func listInstances(ctx context.Context, c *ons.Client) ([]ons.InstanceVO, error) {
	var resources []ons.InstanceVO

	req := ons.CreateOnsInstanceInServiceListRequest()
	req.InitWithApiInfo("Ons", "2019-02-14", "OnsInstanceInServiceList", "ons", "openAPI")
	req.Method = requests.POST

	response, err := c.OnsInstanceInServiceList(req)
	if err != nil {
		return nil, err
	}

	resources = append(resources, response.Data.InstanceVO...)

	return resources, nil
}

// describeInstanceDetail gets details for a single ONS Instance
func describeInstanceDetail(ctx context.Context, c *ons.Client, resource ons.InstanceVO) *InstanceDetail {
	req := ons.CreateOnsInstanceBaseInfoRequest()
	req.InitWithApiInfo("Ons", "2019-02-14", "OnsInstanceBaseInfo", "ons", "openAPI")
	req.Method = requests.POST
	req.InstanceId = resource.InstanceId

	response, err := c.OnsInstanceBaseInfo(req)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to get instance base info", zap.String("instanceId", resource.InstanceId), zap.Error(err))
		return &InstanceDetail{
			Instance: resource,
		}
	}

	return &InstanceDetail{
		Instance:         resource,
		InstanceBaseInfo: response.InstanceBaseInfo,
	}
}
