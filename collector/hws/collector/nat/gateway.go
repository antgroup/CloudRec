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

package nat

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2/model"
	"go.uber.org/zap"
)

func GetGatewayResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NatGateway,
		ResourceTypeName:   "Nat Gateway",
		ResourceGroupType:  constant.NET,
		Desc:               `https://console.huaweicloud.com/apiexplorer/#/openapi/NAT/sdk?api=ListNatGateways`,
		ResourceDetailFunc: GetGatewayDetail,
		RowField: schema.RowField{
			ResourceId:   "$.NatGateway.id",
			ResourceName: "$.NatGateway.name",
		},
		Dimension: schema.Regional,
	}
}

type GatewayDetail struct {
	NatGateway model.NatGatewayResponseBody
}

func GetGatewayDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Nat
	limit := int32(50)
	request := &model.ListNatGatewaysRequest{
		Limit: &limit,
	}
	for {
		response, err := cli.ListNatGateways(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListNatGateways error", zap.Error(err))
			return err
		}

		for _, natGateway := range *response.NatGateways {
			res <- &GatewayDetail{
				NatGateway: natGateway,
			}
		}

		if len(*response.NatGateways) < int(limit) {
			break
		}

		natGateway := (*response.NatGateways)[len(*response.NatGateways)-1]

		*request.Marker = natGateway.Id
	}
	return nil
}
