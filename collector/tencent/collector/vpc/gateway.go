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

package vpc

import (
	"context"

	"github.com/cloudrec/tencent/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
	"go.uber.org/zap"
)

func GetGatewayResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NATGateway,
		ResourceTypeName:   "NAT Gateway",
		ResourceGroupType:  constant.NET,
		Desc:               "https://cloud.tencent.com/document/api/215/36034",
		ResourceDetailFunc: ListNATGatewayResource,
		RowField: schema.RowField{
			ResourceId:   "$.NatGateway.NatGatewayId",
			ResourceName: "$.NatGateway.NatGatewayName",
			Address:      "$.NatGateway.PublicIpAddressSet",
		},
		Dimension: schema.Regional,
	}
}

type GatewayDetail struct {
	NatGateway *vpc.NatGateway
}

func ListNATGatewayResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPC

	request := vpc.NewDescribeNatGatewaysRequest()
	request.Limit = common.Uint64Ptr(100)
	request.Offset = common.Uint64Ptr(0)

	var count uint64
	for {
		response, err := cli.DescribeNatGateways(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeNatGateways error", zap.Error(err))
			return err
		}

		for _, natgw := range response.Response.NatGatewaySet {
			d := &GatewayDetail{
				NatGateway: natgw,
			}
			res <- d
		}

		count += uint64(len(response.Response.NatGatewaySet))
		if count >= *response.Response.TotalCount {
			break
		}

		*request.Offset += *request.Limit
	}

	return nil
}
