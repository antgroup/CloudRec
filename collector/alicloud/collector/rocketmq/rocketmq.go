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

package rocketmq

import (
	"context"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"

	rocketmq20220801 "github.com/alibabacloud-go/rocketmq-20220801/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
)

func GetRocketMQResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.RocketMQ,
		ResourceTypeName:   "RocketMQ",
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               "https://api.aliyun.com/product/RocketMQ",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.instanceId",
			ResourceName: "$.Instance.instanceName",
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
	cli := service.(*collector.Services).RocketMQ

	listInstancesRequest := &rocketmq20220801.ListInstancesRequest{}
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)
	instances, err := cli.ListInstancesWithOptions(listInstancesRequest, headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("ListInstancesWithOptions error", zap.Error(err))
		return err
	}

	if len(instances.Body.Data.List) == 0 {
		log.CtxLogger(ctx).Info("ListInstancesWithOptions no instance")
		return nil
	}

	for _, instance := range instances.Body.Data.List {
		d := Detail{
			RegionId:  cli.RegionId,
			Instance:  getInstance(ctx, cli, instance.InstanceId),
			Acl:       describeACL(ctx, cli, instance.InstanceId),
			WhiteList: describeWhiteList(ctx, cli, instance.InstanceId),
		}

		res <- d
	}
	return nil
}

type Detail struct {
	RegionId  *string
	Instance  *rocketmq20220801.GetInstanceResponseBodyData
	Acl       []*rocketmq20220801.ListInstanceAclResponseBodyDataList
	WhiteList []*string
}

func getInstance(ctx context.Context, cli *rocketmq20220801.Client, id *string) *rocketmq20220801.GetInstanceResponseBodyData {
	response, err := cli.GetInstance(id)
	if err != nil {
		log.CtxLogger(ctx).Error("GetInstance error", zap.Error(err))
		return nil
	}
	return response.Body.Data
}

func describeACL(ctx context.Context, cli *rocketmq20220801.Client, instanceId *string) []*rocketmq20220801.ListInstanceAclResponseBodyDataList {
	listInstanceAclRequest := &rocketmq20220801.ListInstanceAclRequest{
		PageNumber: tea.Int32(1),
		PageSize:   tea.Int32(10000),
	}
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)

	result, err := cli.ListInstanceAclWithOptions(instanceId, listInstanceAclRequest, headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("ListInstanceAclWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Data.List
}

func describeWhiteList(ctx context.Context, cli *rocketmq20220801.Client, instanceId *string) []*string {
	listInstanceIpWhitelistRequest := &rocketmq20220801.ListInstanceIpWhitelistRequest{
		PageNumber: tea.Int32(1),
		PageSize:   tea.Int32(10000),
	}
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)

	result, err := cli.ListInstanceIpWhitelistWithOptions(instanceId, listInstanceIpWhitelistRequest, headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("ListInstanceIpWhitelistWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Data.List
}
