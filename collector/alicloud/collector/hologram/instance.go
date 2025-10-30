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

package hologram

import (
	"context"
	hologram20220601 "github.com/alibabacloud-go/hologram-20220601/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetHologramInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.HologramInstance,
		ResourceTypeName:   collector.HologramInstance,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/gpdb`,
		ResourceDetailFunc: GetHologramInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Dimension: schema.Regional,
	}
}

type InstanceDetail struct {
	Instance *hologram20220601.ListInstancesResponseBodyInstanceList
}

func GetHologramInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Hologram

	instances := listInstances(ctx, cli)

	for _, instance := range instances {
		res <- InstanceDetail{
			Instance: instance,
		}
	}

	return nil
}

func listInstances(ctx context.Context, cli *hologram20220601.Client) []*hologram20220601.ListInstancesResponseBodyInstanceList {
	request := &hologram20220601.ListInstancesRequest{}

	response, err := cli.ListInstances(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListInstances error", zap.Error(err))
		return nil
	}

	return response.Body.InstanceList
}
