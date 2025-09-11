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

package eipanycast

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eipanycast"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetAnycastEipAddressResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.AnycastEipAddress,
		ResourceTypeName:   collector.AnycastEipAddress,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Eipanycast`,
		ResourceDetailFunc: GetAnycastEipAddressDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Anycast.AnycastId",
			ResourceName: "$.Anycast.Name",
			Address:      "$.Anycast.IpAddress",
		},
		Dimension: schema.Global,
	}
}

type AnycastEipAddressDetail struct {
	Anycast eipanycast.Anycast
}

func GetAnycastEipAddressDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Eipanycast

	anycastList := listAnycastEipAddresses(ctx, cli)
	for _, anycast := range anycastList {
		anycastDetail := describeAnycastEipAddress(ctx, cli, anycast.AnycastId)

		d := AnycastEipAddressDetail{
			Anycast: anycastDetail,
		}
		res <- d
	}

	return nil
}

func describeAnycastEipAddress(ctx context.Context, cli *eipanycast.Client, anycastId string) eipanycast.Anycast {
	request := eipanycast.CreateDescribeAnycastEipAddressRequest()
	request.Scheme = "https"
	request.AnycastId = anycastId

	response, err := cli.DescribeAnycastEipAddress(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAnycastEipAddress error", zap.Error(err))
		return eipanycast.Anycast{}
	}

	return eipanycast.Anycast{
		Status:                 response.Status,
		Description:            response.Description,
		InstanceChargeType:     response.InstanceChargeType,
		CreateTime:             response.CreateTime,
		BusinessStatus:         response.BusinessStatus,
		InternetChargeType:     response.InternetChargeType,
		Name:                   response.Name,
		AnycastId:              response.AnycastId,
		ServiceLocation:        response.ServiceLocation,
		Bandwidth:              response.Bandwidth,
		IpAddress:              response.IpAddress,
		Bid:                    response.Bid,
		AliUid:                 response.AliUid,
		ResourceGroupId:        response.ResourceGroupId,
		AnycastEipBindInfoList: response.AnycastEipBindInfoList,
		Tags:                   response.Tags,
	}
}

func listAnycastEipAddresses(ctx context.Context, cli *eipanycast.Client) (anycastList []eipanycast.Anycast) {
	request := eipanycast.CreateListAnycastEipAddressesRequest()
	request.Scheme = "https"
	request.MaxResults = requests.NewInteger(100)
	for {
		response, err := cli.ListAnycastEipAddresses(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListAnycastEipAddresses error", zap.Error(err))
			return
		}
		anycastList = append(anycastList, response.AnycastList...)
		if response.NextToken == "" {
			break
		}
		request.NextToken = response.NextToken
	}

	return anycastList
}
