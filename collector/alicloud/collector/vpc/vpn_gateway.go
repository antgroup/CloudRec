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
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetVPNGatewayResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.VPNGateway,
		ResourceTypeName:   collector.VPNGateway,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Vpc`,
		ResourceDetailFunc: GetVPNGatewayDetail,
		RowField: schema.RowField{
			ResourceId:   "$.VpnGateway.VpnGatewayId",
			ResourceName: "$.VpnGateway.Name",
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
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"cn-chengdu",
			"cn-hongkong",
			"ap-northeast-1",
			"ap-southeast-1",
			"ap-southeast-3",
			"ap-southeast-5",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"eu-central-1",
			"ap-northeast-2",
			"ap-southeast-6",
			"ap-southeast-7",
			"me-central-1",
			"cn-fuzhou",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

type VPNGatewayDetail struct {
	VpnGateway      vpc.VpnGateway
	VpnRouteEntries []vpc.VpnRouteEntry
}

func GetVPNGatewayDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPC

	request := vpc.CreateDescribeVpnGatewaysRequest()
	request.PageSize = requests.NewInteger(50)
	request.PageNumber = requests.NewInteger(1)

	count := 0
	for {
		response, err := cli.DescribeVpnGateways(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeVpnGateways error", zap.Error(err))
			return err
		}

		for _, gateway := range response.VpnGateways.VpnGateway {

			// Get VPN route entries
			vpnRouteEntries := getVpnRouteEntries(ctx, cli, gateway.VpnGatewayId)

			detail := &VPNGatewayDetail{
				VpnGateway:      gateway,
				VpnRouteEntries: vpnRouteEntries,
			}
			res <- detail
		}

		count += len(response.VpnGateways.VpnGateway)
		if count >= response.TotalCount {
			break
		}

		request.PageNumber = requests.NewInteger(response.PageNumber + 1)
	}

	return nil
}

func getVpnRouteEntries(ctx context.Context, cli *vpc.Client, vpnGatewayId string) (vpnRouteEntries []vpc.VpnRouteEntry) {
	request := vpc.CreateDescribeVpnRouteEntriesRequest()
	request.VpnGatewayId = vpnGatewayId
	request.PageSize = requests.NewInteger(50)
	request.PageNumber = requests.NewInteger(1)

	count := 0
	for {
		response, err := cli.DescribeVpnRouteEntries(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeVpnRouteEntries error", zap.Error(err), zap.String("vpnGatewayId", vpnGatewayId))
			return nil
		}
		vpnRouteEntries = append(vpnRouteEntries, response.VpnRouteEntries.VpnRouteEntry...)

		count += len(response.VpnRouteEntries.VpnRouteEntry)
		if count >= response.TotalCount {
			break
		}

		request.PageNumber = requests.NewInteger(response.PageNumber + 1)
	}

	return vpnRouteEntries
}
