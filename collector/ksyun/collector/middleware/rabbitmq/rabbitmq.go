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

package rabbitmq

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	rabbitmq "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/rabbitmq/v20191017"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type Detail struct {
	Instance       any
	SecurityGroups []any
}

func GetRabbitMQResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.RabbitMQ,
		ResourceTypeName:  collector.RabbitMQ,
		ResourceGroupType: constant.MIDDLEWARE,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/135/1068`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).RabbitMQ
			request := rabbitmq.NewDescribeInstancesRequest()
			limit := 100
			request.Limit = common.IntPtr(limit)
			request.Offset = common.IntPtr(0)
			count := 0

			for {
				responseStr := cli.DescribeInstancesWithContext(ctx, request)
				collector.ShowResponse(ctx, "RabbitMQ", "DescribeInstances", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("RabbitMQ DescribeInstances error", zap.Error(err))
					return err
				}

				response := rabbitmq.NewDescribeInstancesResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("RabbitMQ DescribeInstances decode error", zap.Error(err))
					return err
				}
				if len(response.Data.Instances) == 0 {
					break
				}

				for i := range response.Data.Instances {
					item := &response.Data.Instances[i]
					res <- Detail{
						Instance:       item,
						SecurityGroups: describeSecurityGroups(ctx, cli, item.InstanceId),
					}
				}
				count += len(response.Data.Instances)
				if count >= *response.Data.Total {
					break
				}
				request.Offset = common.IntPtr(count)
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Regions: []string{
			"cn-beijing-6", // 华北1（北京）
		},
		Dimension: schema.Regional,
	}
}

func describeSecurityGroups(ctx context.Context, cli *rabbitmq.Client, instanceId *string) (ans []any) {
	request := rabbitmq.NewDescribeSecurityGroupRulesRequest()
	request.InstanceId = instanceId

	responseStr := cli.DescribeSecurityGroupRulesWithContext(ctx, request)
	collector.ShowResponse(ctx, "RabbitMQ", "DescribeSecurityGroupRules", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("RabbitMQ DescribeSecurityGroupRules error", zap.Error(err))
		return ans
	}

	response := rabbitmq.NewDescribeSecurityGroupRulesResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("RabbitMQ DescribeSecurityGroupRules decode error", zap.Error(err))
		return ans
	}

	for i := range response.Data {
		ans = append(ans, &response.Data[i])
	}

	return ans
}
