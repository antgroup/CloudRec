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

package ens

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ens"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"strconv"
)

func GetNatGatewayResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ENSNatGateway,
		ResourceTypeName:   "ENS NAT Gateway",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Ens`,
		ResourceDetailFunc: ListNatGatewayResource,
		RowField: schema.RowField{
			ResourceId:   "$.NatGateway.NatGatewayId",
			ResourceName: "$.NatGateway.Name",
		},
		Regions:   []string{"cn-hangzhou"},
		Dimension: schema.Global,
	}
}

type NatGatewayDetail struct {
	NatGateway          ens.NatGateway
	ForwardTableEntries []ens.ForwardTableEntry
}

func ListNatGatewayResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ENS
	describeNatGatewaysRequest := ens.CreateDescribeNatGatewaysRequest()
	describeNatGatewaysResponse, err := cli.DescribeNatGateways(describeNatGatewaysRequest)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeNatGateways error", zap.Error(err))
		return err
	}
	for describeNatGatewaysResponse.PageSize*describeNatGatewaysResponse.PageNumber <= describeNatGatewaysResponse.TotalCount {
		for _, natGateway := range describeNatGatewaysResponse.NatGateways {
			natGatewayDetail := NatGatewayDetail{
				NatGateway:          natGateway,
				ForwardTableEntries: describeForwardTableEntries(ctx, cli, natGateway.NatGatewayId),
			}

			res <- natGatewayDetail
		}
		describeNatGatewaysRequest.PageNumber = requests.NewInteger(describeNatGatewaysResponse.PageNumber + 1)
		describeNatGatewaysResponse, err = cli.DescribeNatGateways(describeNatGatewaysRequest)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeNatGateways error", zap.Error(err))
			return err
		}
	}
	return nil
}

func describeForwardTableEntries(ctx context.Context, cli *ens.Client, natgwid string) (forwardTableEntries []ens.ForwardTableEntry) {
	describeForwardTableEntriesRequest := ens.CreateDescribeForwardTableEntriesRequest()
	describeForwardTableEntriesRequest.NatGatewayId = natgwid

	describeForwardTableEntriesResponse, err := cli.DescribeForwardTableEntries(describeForwardTableEntriesRequest)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeForwardTableEntries error", zap.Error(err))
		return forwardTableEntries
	}

	pageSize, _ := strconv.Atoi(describeForwardTableEntriesResponse.PageSize)
	pageNumber, _ := strconv.Atoi(describeForwardTableEntriesResponse.PageNumber)
	totalCount, _ := strconv.Atoi(describeForwardTableEntriesResponse.TotalCount)

	for pageSize*pageNumber <= totalCount {
		forwardTableEntries = append(forwardTableEntries, describeForwardTableEntriesResponse.ForwardTableEntries...)

		describeForwardTableEntriesRequest.PageNumber = requests.NewInteger(pageNumber + 1)
		describeForwardTableEntriesResponse, err = cli.DescribeForwardTableEntries(describeForwardTableEntriesRequest)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeForwardTableEntries error", zap.Error(err))
			return forwardTableEntries
		}
		pageSize, _ = strconv.Atoi(describeForwardTableEntriesResponse.PageSize)
		pageNumber, _ = strconv.Atoi(describeForwardTableEntriesResponse.PageNumber)
		totalCount, _ = strconv.Atoi(describeForwardTableEntriesResponse.TotalCount)
	}
	return forwardTableEntries
}
