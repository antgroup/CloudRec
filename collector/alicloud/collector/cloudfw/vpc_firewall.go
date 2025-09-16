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

package cloudfw

import (
	"context"
	cloudfw20171207 "github.com/alibabacloud-go/cloudfw-20171207/v8/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"strconv"
)

func GetVpcFWResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.VpcFirewall,
		ResourceTypeName:   "VPC Firewall",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/Cloudfw`,
		ResourceDetailFunc: GetVpcFirewallDetail,
		Dimension:          schema.Global,
		RowField: schema.RowField{
			ResourceId:   "$.VpcFirewall.VpcFirewallId",
			ResourceName: "$.VpcFirewall.VpcFirewallName",
		},
	}
}

type VpcFirewallDetail struct {
	VpcFirewall *cloudfw20171207.DescribeVpcFirewallListResponseBodyVpcFirewalls
}

func GetVpcFirewallDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Cloudfw

	vpcFirewallList := describeVpcFirewallList(ctx, cli)

	for _, vpcFirewall := range vpcFirewallList {
		res <- &VpcFirewallDetail{
			VpcFirewall: vpcFirewall,
		}
	}

	return nil
}

func describeVpcFirewallList(ctx context.Context, cli *cloudfw20171207.Client) (vpcFirewallList []*cloudfw20171207.DescribeVpcFirewallListResponseBodyVpcFirewalls) {
	request := &cloudfw20171207.DescribeVpcFirewallListRequest{}

	for {
		response, err := cli.DescribeVpcFirewallList(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("describe vpc firewall list error", zap.Error(err))
			return nil
		}
		vpcFirewallList = append(vpcFirewallList, response.Body.VpcFirewalls...)

		if int32(len(vpcFirewallList)) >= *response.Body.TotalCount {
			break
		}

		currentPage, err := strconv.Atoi(*request.CurrentPage)
		if err != nil {
			log.CtxLogger(ctx).Warn("convert current page error", zap.Error(err))
			break
		}
		request.CurrentPage = tea.String(strconv.Itoa(currentPage + 1))
	}

	return vpcFirewallList
}
