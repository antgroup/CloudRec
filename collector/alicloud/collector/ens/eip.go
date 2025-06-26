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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ens"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetEipAddressesResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ENSEip,
		ResourceTypeName:   "ENS EIP",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Ens`,
		ResourceDetailFunc: ListEipAddressesResource,
		RowField: schema.RowField{
			ResourceId:   "$.EipAddress.InstanceId",
			ResourceName: "$.EipAddress.Name",
			Address:      "$.EipAddress.IpAddress",
		},
		Regions:   []string{"cn-hangzhou"},
		Dimension: schema.Global,
	}
}

type EipAddressDetail struct {
	EipAddress ens.EipAddress
}

func ListEipAddressesResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ENS
	describeEnsEipAddressesRequest := ens.CreateDescribeEnsEipAddressesRequest()
	describeEnsEipAddressesResponse, err := cli.DescribeEnsEipAddresses(describeEnsEipAddressesRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeEnsEipAddresses error", zap.Error(err))
		return err
	}
	for describeEnsEipAddressesResponse.PageSize*describeEnsEipAddressesResponse.PageNumber <= describeEnsEipAddressesResponse.TotalCount {
		for _, eipAddress := range describeEnsEipAddressesResponse.EipAddresses.EipAddress {
			eipAddressDetail := EipAddressDetail{
				EipAddress: eipAddress,
			}

			res <- eipAddressDetail
		}
		describeEnsEipAddressesRequest.PageNumber = requests.NewInteger(describeEnsEipAddressesResponse.PageNumber + 1)
		describeEnsEipAddressesResponse, err = cli.DescribeEnsEipAddresses(describeEnsEipAddressesRequest)
		if err != nil {
			return err
		}
	}

	return nil
}
