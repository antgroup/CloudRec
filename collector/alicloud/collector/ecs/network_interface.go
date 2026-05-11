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

package ecs

import (
	"context"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// Detail is a flat alias of ecs.NetworkInterfaceSet so the persisted JSON keeps
// the API's top-level field names (NetworkInterfaceId, PrivateIpSets, ...).
// This matches the shape produced by the legacy n8n pipeline, so JSONPath
// expressions like $.NetworkInterfaceId and $.PrivateIpSets.PrivateIpSet[*]
// keep working against records written by this collector.
type NetworkInterfaceDetail = ecs.NetworkInterfaceSet

func GetNetworkInterfaceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ENI,
		ResourceTypeName:   collector.ENI,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Ecs`,
		ResourceDetailFunc: ListNetworkInterfaceResource,
		RowField: schema.RowField{
			ResourceId:   "$.NetworkInterfaceId",
			ResourceName: "$.NetworkInterfaceName",
			Address:      "$.AssociatedPublicIp.PublicIpAddress",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-nanjing",
			"cn-fuzhou",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"cn-wuhan-lr",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-zhengzhou-jva",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"us-southeast-1",
			"na-south-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

// ListNetworkInterfaceResource lists ALL ENIs in a region (no InstanceId
// filter), so it captures unattached ENIs and ENIs attached to non-ECS
// resources (NAT gateway, RDS, SLB, ...) — the existing per-instance lookup
// in ecs.go only covers ENIs attached to ECS instances.
func ListNetworkInterfaceResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ECS
	req := ecs.CreateDescribeNetworkInterfacesRequest()
	req.Scheme = "HTTPS"
	req.PageSize = requests.NewInteger(constant.DefaultPageSize)
	req.PageNumber = requests.NewInteger(constant.DefaultPage)

	count := 0
	for {
		resp, err := cli.DescribeNetworkInterfaces(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeNetworkInterfaces error", zap.Error(err))
			return err
		}
		for i := range resp.NetworkInterfaceSets.NetworkInterfaceSet {
			res <- resp.NetworkInterfaceSets.NetworkInterfaceSet[i]
		}
		count += len(resp.NetworkInterfaceSets.NetworkInterfaceSet)
		if count >= resp.TotalCount || len(resp.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return nil
}
