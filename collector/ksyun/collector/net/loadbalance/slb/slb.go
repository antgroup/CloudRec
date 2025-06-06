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

package slb

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	slb "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/slb/v20160304"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type DescribeListenersResponse struct {
	RequestId   *string `json:"RequestId" name:"RequestId"`
	NextToken   *string `json:"NextToken" name:"NextToken"`
	ListenerSet []any   `json:"ListenerSet" name:"ListenerSet"`
}

type ListenerDetail struct {
	Listener any
	Acls     []any
}

type KSyunSLBDetail struct {
	SLB       any
	Listeners []*ListenerDetail
}

func GetSLBResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.SLB,
		ResourceTypeName:  collector.SLB,
		ResourceGroupType: constant.NET,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/93/1013`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).SLB
			request := slb.NewDescribeLoadBalancersRequest()
			request.MaxResults = common.IntPtr(100)
			count := 0
			for {
				responseStr := cli.DescribeLoadBalancersWithContext(ctx, request)
				collector.ShowResponse(ctx, "SLB", "DescribeLoadBalancers", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("SLB DescribeLoadBalancers error", zap.Error(err))
					return err
				}

				response := slb.NewDescribeLoadBalancersResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("SLB DescribeLoadBalancersResponse decode error", zap.Error(err))
					return err
				}
				if len(response.LoadBalancerDescriptions) == 0 {
					break
				}

				for i := range response.LoadBalancerDescriptions {
					item := &response.LoadBalancerDescriptions[i]
					res <- &KSyunSLBDetail{
						SLB:       item,
						Listeners: describeSlbListeners(ctx, cli, item.LoadBalancerId),
					}
				}
				count += len(response.LoadBalancerDescriptions)
				if response.NextToken == nil || len(response.LoadBalancerDescriptions) < *request.MaxResults || count > *response.TotalCount {
					break
				}

				request.NextToken = response.NextToken
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.SLB.LoadBalancerId",
			ResourceName: "$.SLB.LoadBalancerName",
			Address:      "$.SLB.PublicIp",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"cn-central-1",    // 华中1（武汉）
			"cn-hongkong-2",   // 香港
			"ap-singapore-1",  // 新加坡
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-southwest-1",  // 西南1（重庆）
			"cn-northwest-1",  // 西北1（庆阳）
			"cn-northwest-2",  // 西北2区（庆阳）
			"cn-northwest-3",  // 西北3区（宁夏）
			"cn-north-vip1",   // 华北专属1区（天津-小米）
			"cn-ningbo-1",     // 华东2（宁波）
			"cn-northwest-4",  // 西北4（海东）
		},
		Dimension: schema.Regional,
	}
}

func describeSlbListeners(ctx context.Context, cli *slb.Client, lbId *string) (listeners []*ListenerDetail) {
	request := slb.NewDescribeListenersRequest()
	request.MaxResults = common.IntPtr(100)
	request.Filter = []*slb.DescribeListenersFilter{
		1: {
			Name:  common.StringPtr("load-balancer-id"),
			Value: []*string{1: lbId},
		},
	}

	for {
		responseStr := cli.DescribeListenersWithContext(ctx, request)
		collector.ShowResponse(ctx, "SLB", "DescribeListeners", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("SLB DescribeListeners error", zap.Error(err))
			return listeners
		}

		response := slb.NewDescribeListenersResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("SLB DescribeListenersResponse decode error", zap.Error(err))
			return
		}
		localResp := &DescribeListenersResponse{}
		_ = json.Unmarshal([]byte(responseStr), localResp)
		if len(response.ListenerSet) == 0 || len(localResp.ListenerSet) == 0 || len(response.ListenerSet) != len(localResp.ListenerSet) {
			return
		}

		for i := range response.ListenerSet {
			listeners = append(listeners, &ListenerDetail{
				Listener: localResp.ListenerSet[i],
				Acls:     describeSlbAcls(ctx, cli, response.ListenerSet[i].LoadBalancerAclId),
			})
		}
		if response.NextToken == nil || len(response.ListenerSet) < *request.MaxResults {
			break
		}

		request.NextToken = response.NextToken
	}
	return
}

func describeSlbAcls(ctx context.Context, cli *slb.Client, aclId *string) (acls []any) {
	request := slb.NewDescribeLoadBalancerAclsRequest()
	request.MaxResults = common.IntPtr(100)
	request.LoadBalancerAclId = []*string{
		1: aclId,
	}

	for {
		responseStr := cli.DescribeLoadBalancerAclsWithContext(ctx, request)
		collector.ShowResponse(ctx, "SLB", "DescribeLoadBalancerAcls", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("SLB DescribeLoadBalancerAcls error", zap.Error(err))
			return acls
		}

		response := slb.NewDescribeLoadBalancerAclsResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("SLB DescribeLoadBalancerAclsResponse decode error", zap.Error(err))
			return
		}
		if len(response.LoadBalancerAclSet) == 0 {
			return acls
		}

		for i := range response.LoadBalancerAclSet {
			acls = append(acls, &response.LoadBalancerAclSet[i])
		}
		if response.NextToken == nil || len(response.LoadBalancerAclSet) < *request.MaxResults {
			break
		}

		request.NextToken = response.NextToken
	}
	return acls
}
