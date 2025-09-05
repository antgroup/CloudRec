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

package hbase

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/hbase"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetHbaseResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Hbase,
		ResourceTypeName:   collector.Hbase,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/HBase`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"cn-guangzhou",
			"ap-southeast-3",
			"ap-northeast-1",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Hbase

	request := hbase.CreateDescribeInstancesRequest()

	response, err := cli.DescribeInstances(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstances error", zap.Error(err))
		return err
	}

	for _, i := range response.Instances.Instance {
		res <- &Detail{
			Instance:     i,
			ConnAddrInfo: describeEndpoints(ctx, cli, i.InstanceId),
			Group:        describeIpWhitelist(ctx, cli, i.InstanceId),
		}
	}
	return nil
}

type Detail struct {
	Instance     hbase.Instance
	ConnAddrInfo []hbase.ConnAddrInfo
	Group        []hbase.Group
}

// DescribeEndpoints 查询HBase实例的数据库连接信息
func describeEndpoints(ctx context.Context, cli *hbase.Client, clusterId string) (connAddrInfo []hbase.ConnAddrInfo) {
	request := hbase.CreateDescribeEndpointsRequest()
	request.Scheme = "https"
	request.ClusterId = clusterId

	response, err := cli.DescribeEndpoints(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeEndpoints error", zap.Error(err))
		return
	}

	return response.ConnAddrs.ConnAddrInfo
}

// Get the cluster whitelist information list based on the cluster ID
func describeIpWhitelist(ctx context.Context, cli *hbase.Client, clusterId string) (group []hbase.Group) {
	request := hbase.CreateDescribeIpWhitelistRequest()
	request.Scheme = "https"
	request.ClusterId = clusterId

	response, err := cli.DescribeIpWhitelist(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeIpWhitelist error", zap.Error(err))
		return
	}

	return response.Groups.Group
}
