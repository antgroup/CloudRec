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

package eip

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
	EipAddress *vpc.EipAddress
}

func GetEIPResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EIP,
		ResourceTypeName:   collector.EIP,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Vpc`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.EipAddress.IpAddress",
			ResourceName: "$.EipAddress.Name",
			Address:      "$.EipAddress.IpAddress",
		},
		Regions:   collectorvpc.Regions,
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPC
	req := vpc.CreateDescribeEipAddressesRequest()
	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		resp, err := cli.DescribeEipAddresses(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeEipAddresses error", zap.Error(err))
			return err
		}
		count += len(resp.EipAddresses.EipAddress)

		for _, eip := range resp.EipAddresses.EipAddress {
			d := &Detail{
				EipAddress: &eip,
			}

			res <- d
		}
		if count >= resp.TotalCount || len(resp.EipAddresses.EipAddress) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}
	return nil
}
