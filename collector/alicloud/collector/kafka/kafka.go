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

package kafka

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alikafka"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetKafkaResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Kafka,
		ResourceTypeName:   collector.Kafka,
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               "https://api.aliyun.com/product/alikafka",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.InstanceVO.InstanceId",
			ResourceName: "$.InstanceVO.Name",
			Address:      "$.InstanceVO.DomainEndpoint",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
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
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Alikafka

	request := alikafka.CreateGetInstanceListRequest()

	response, err := cli.GetInstanceList(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetInstanceList error", zap.Error(err))
		return err
	}

	for _, i := range response.InstanceList.InstanceVO {
		res <- &Detail{
			InstanceVO:  i,
			AllowedList: getAllowedIpList(ctx, cli, i.InstanceId),
		}
	}
	return nil
}

type Detail struct {
	InstanceVO  alikafka.InstanceVO
	AllowedList alikafka.AllowedList
}

// getAllowedIpList Get IP whitelist
func getAllowedIpList(ctx context.Context, cli *alikafka.Client, instanceId string) (res alikafka.AllowedList) {
	request := alikafka.CreateGetAllowedIpListRequest()
	request.Scheme = "https"
	request.InstanceId = instanceId

	response, err := cli.GetAllowedIpList(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAllowedIpList error", zap.Error(err))
		return
	}

	return response.AllowedList
}
