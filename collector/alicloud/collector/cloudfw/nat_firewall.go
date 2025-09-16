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

func GetNatFWResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NatFirewall,
		ResourceTypeName:   "Nat Firewall",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/Cloudfw`,
		ResourceDetailFunc: GetNatFirewallDetail,
		Dimension:          schema.Global,
		RowField: schema.RowField{
			ResourceId:   "$.NatFirewall.ProxyId",
			ResourceName: "$.NatFirewall.ProxyName",
		},
	}
}

type NatFirewallDetail struct {
	NatFirewall     *cloudfw20171207.DescribeNatFirewallListResponseBodyNatFirewallList
	ControlPolicies NatFirewallControlPolicy
}

type NatFirewallControlPolicy struct {
	In  []*cloudfw20171207.DescribeNatFirewallControlPolicyResponseBodyPolicys
	Out []*cloudfw20171207.DescribeNatFirewallControlPolicyResponseBodyPolicys
}

func GetNatFirewallDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Cloudfw

	natFirewallList := describeNatFirewallList(ctx, cli)

	for _, natFirewall := range natFirewallList {
		res <- &NatFirewallDetail{
			NatFirewall: natFirewall,
			ControlPolicies: NatFirewallControlPolicy{
				In:  describeNatFirewallControlPolicy(ctx, cli, *natFirewall.NatGatewayId, "in"),
				Out: describeNatFirewallControlPolicy(ctx, cli, *natFirewall.NatGatewayId, "out"),
			},
		}
	}

	return nil
}

func describeNatFirewallList(ctx context.Context, cli *cloudfw20171207.Client) (natFirewallList []*cloudfw20171207.DescribeNatFirewallListResponseBodyNatFirewallList) {
	request := &cloudfw20171207.DescribeNatFirewallListRequest{
		PageNo: tea.Int64(1),
	}

	var count int32 = 0
	for {
		resp, err := cli.DescribeNatFirewallList(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("describe nat firewall list error", zap.Error(err))
			return nil
		}
		natFirewallList = append(natFirewallList, resp.Body.NatFirewallList...)
		count += int32(len(natFirewallList))
		if count >= *resp.Body.TotalCount || len(resp.Body.NatFirewallList) == 0 {
			break
		}
		request.PageNo = tea.Int64(*request.PageNo + 1)
	}

	return natFirewallList
}

func describeNatFirewallControlPolicy(ctx context.Context, cli *cloudfw20171207.Client, natGatewayId string, direction string) (natFirewallControlPolicies []*cloudfw20171207.DescribeNatFirewallControlPolicyResponseBodyPolicys) {
	request := &cloudfw20171207.DescribeNatFirewallControlPolicyRequest{
		NatGatewayId: tea.String(natGatewayId),
		Direction:    tea.String(direction),
		CurrentPage:  tea.String("1"),
	}

	var count = 0
	var resp *cloudfw20171207.DescribeNatFirewallControlPolicyResponse
	for {
		var err error
		resp, err = cli.DescribeNatFirewallControlPolicy(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("describe nat firewall control policy error", zap.Error(err))
			return
		}
		natFirewallControlPolicies = append(natFirewallControlPolicies, resp.Body.Policys...)

		count += len(resp.Body.Policys)
		totalCount, err := strconv.Atoi(*resp.Body.TotalCount)
		if err != nil {
			log.CtxLogger(ctx).Warn("convert total count error", zap.Error(err))
			break
		}
		if count >= totalCount || len(resp.Body.Policys) == 0 {
			break
		}
		currentPage, err := strconv.Atoi(*request.CurrentPage)
		if err != nil {
			log.CtxLogger(ctx).Warn("convert current page error", zap.Error(err))
			break
		}
		request.CurrentPage = tea.String(strconv.Itoa(currentPage + 1))
	}

	return natFirewallControlPolicies
}
