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
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ons"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

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
	InstanceBaseInfo *ons.InstanceBaseInfo
}

// GetInstanceDetail gets ONS Instance details
func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Ons

	resources, err := listInstances(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list instances", zap.Error(err))
		return err
	}

	for _, resource := range resources {

		res <- &InstanceDetail{
			Instance:         resource,
			InstanceBaseInfo: describeInstance(ctx, client, resource),
		}
	}
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

// describeInstance gets details for a single ONS Instance
func describeInstance(ctx context.Context, c *ons.Client, resource ons.InstanceVO) *ons.InstanceBaseInfo {
	req := ons.CreateOnsInstanceBaseInfoRequest()
	req.InitWithApiInfo("Ons", "2019-02-14", "OnsInstanceBaseInfo", "ons", "openAPI")
	req.Method = requests.POST
	req.InstanceId = resource.InstanceId

	response, err := c.OnsInstanceBaseInfo(req)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to get instance base info", zap.String("instanceId", resource.InstanceId), zap.Error(err))
		return nil
	}

	return &response.InstanceBaseInfo
}
