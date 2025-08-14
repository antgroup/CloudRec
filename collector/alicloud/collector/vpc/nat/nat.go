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
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/cloudrec/alicloud/collector"
	collectorvpc "github.com/cloudrec/alicloud/collector/vpc"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

type Detail struct {
	NatGateway        vpc.NatGateway
	ForwardTableEntry []vpc.ForwardTableEntry
	SnatTableEntry    []vpc.SnatTableEntry
}

func GetNatResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NAT,
		ResourceTypeName:   collector.NAT,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Vpc`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.NatGateway.NatGatewayId",
			ResourceName: "$.NatGateway.Name",
		},
		Regions:   collectorvpc.Regions,
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPC
	req := vpc.CreateDescribeNatGatewaysRequest()
	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		resp, err := cli.DescribeNatGateways(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeNatGateways error", zap.Error(err))
			return err
		}
		count += len(resp.NatGateways.NatGateway)
		for _, gateway := range resp.NatGateways.NatGateway {
			d := &Detail{
				NatGateway:        gateway,
				ForwardTableEntry: describeForwardTableEntries(ctx, cli, gateway.ForwardTableIds.ForwardTableId),
				SnatTableEntry:    describeSnatTableEntries(ctx, cli, gateway.ForwardTableIds.ForwardTableId),
			}
			res <- d
		}
		if count >= resp.TotalCount || len(resp.NatGateways.NatGateway) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return nil
}

// describeForwardTableEntries Query created DNAT entries
func describeForwardTableEntries(ctx context.Context, client *vpc.Client, forwardTableId []string) (forwardTableEntry []vpc.ForwardTableEntry) {
	for _, tableId := range forwardTableId {
		req := vpc.CreateDescribeForwardTableEntriesRequest()
		req.ForwardTableId = tableId
		req.PageSize = requests.NewInteger(50)
		req.PageNumber = requests.NewInteger(1)
		count := 0
		for {
			resp, err := client.DescribeForwardTableEntries(req)
			if err != nil {
				log.CtxLogger(ctx).Error("DescribeForwardTableEntries error", zap.Error(err))
				return
			}
			count += len(resp.ForwardTableEntries.ForwardTableEntry)
			forwardTableEntry = append(forwardTableEntry, resp.ForwardTableEntries.ForwardTableEntry...)
			if count == resp.TotalCount {
				break
			}
			req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
		}
	}

	return forwardTableEntry
}

// describeSnatTableEntries Query created SNAT entries
func describeSnatTableEntries(ctx context.Context, client *vpc.Client, forwardTableId []string) (snatTableEntry []vpc.SnatTableEntry) {
	for _, tableId := range forwardTableId {
		req := vpc.CreateDescribeSnatTableEntriesRequest()
		req.SnatTableId = tableId
		req.PageSize = requests.NewInteger(50)
		req.PageNumber = requests.NewInteger(1)
		count := 0
		for {
			resp, err := client.DescribeSnatTableEntries(req)
			if err != nil {
				log.CtxLogger(ctx).Error("DescribeSnatTableEntries error", zap.Error(err))
				return
			}
			count += len(resp.SnatTableEntries.SnatTableEntry)

			snatTableEntry = append(snatTableEntry, resp.SnatTableEntries.SnatTableEntry...)
			if count >= resp.TotalCount {
				break
			}
			req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
		}
	}

	return snatTableEntry
}
