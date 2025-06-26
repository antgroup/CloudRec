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
	"github.com/alicloud-sqa/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"go.uber.org/zap"
)

func GetEcsData() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECS,
		ResourceTypeName:   "ECS",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               `https://api.aliyun.com/product/Ecs`,
		ResourceDetailFunc: ListEcsResource,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Instance            ecs.Instance
	SecurityGroups      []*SecurityGroup
	Disks               []ecs.Disk
	NetworkInterfaceSet []ecs.NetworkInterfaceSet
}

func ListEcsResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).EcsClient
	req := ecs.CreateDescribeInstancesRequest()
	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	req.Scheme = "HTTPS"
	req.QueryParams["product"] = "Ecs"
	req.SetHTTPSInsecure(true)

	count := 0
	for {
		response, err := cli.DescribeInstances(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeInstances error", zap.Error(err))
			return err
		}
		for _, i := range response.Instances.Instance {
			d := Detail{
				Instance:            i,
				Disks:               describeDisks(ctx, cli, i.InstanceId),
				NetworkInterfaceSet: describeNetworkInterfaces(ctx, cli, i.InstanceId),
			}

			res <- d
			count++
		}
		if count >= response.TotalCount {
			break
		}
		req.PageNumber = requests.NewInteger(response.PageNumber + 1)
	}

	return nil
}

func describeDisks(ctx context.Context, client *ecs.Client, instanceId string) (disks []ecs.Disk) {
	req := ecs.CreateDescribeDisksRequest()
	req.InstanceId = instanceId
	req.PageSize = requests.NewInteger(constant.DefaultPageSize)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		response, err := client.DescribeDisks(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDisks error", zap.Error(err))
			return nil
		}
		disks = append(disks, response.Disks.Disk...)
		count += len(response.Disks.Disk)
		if count >= response.TotalCount || len(response.Disks.Disk) < constant.DefaultPageSize {
			break
		}
		req.PageNumber = requests.NewInteger(response.PageNumber + 1)
	}

	return disks

}

func describeNetworkInterfaces(ctx context.Context, cli *ecs.Client, instanceId string) (networkInterfaceSet []ecs.NetworkInterfaceSet) {
	req := ecs.CreateDescribeNetworkInterfacesRequest()
	req.Scheme = "HTTPS"
	req.QueryParams["product"] = "Ecs"
	req.SetHTTPSInsecure(true)
	req.PageSize = requests.NewInteger(constant.DefaultPageSize)
	req.PageNumber = requests.NewInteger(constant.DefaultPage)
	req.InstanceId = instanceId
	count := 0
	for {
		resp, err := cli.DescribeNetworkInterfaces(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeNetworkInterfaces error", zap.Error(err))
			return nil
		}
		count += len(resp.NetworkInterfaceSets.NetworkInterfaceSet)

		networkInterfaceSet = append(networkInterfaceSet, resp.NetworkInterfaceSets.NetworkInterfaceSet...)
		if count >= resp.TotalCount || len(resp.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return
}
