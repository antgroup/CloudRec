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

package alb

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
	RequestId      *string `json:"RequestId" name:"RequestId"`
	NextToken      *string `json:"NextToken" name:"NextToken"`
	AlbListenerSet []any   `json:"AlbListenerSet" name:"AlbListenerSet"`
}

type ListenerDetail struct {
	Listener any
	Acls     []any
}

type KSyunALBDetail struct {
	ALB       any
	Listeners []*ListenerDetail
}

func GetALBResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.ALB,
		ResourceTypeName:  collector.ALB,
		ResourceGroupType: constant.NET,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/93/1013`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).SLB
			request := slb.NewDescribeAlbsRequest()
			request.MaxResults = common.IntPtr(100)

			for {
				responseStr := cli.DescribeAlbsWithContext(ctx, request)
				collector.ShowResponse(ctx, "ALB", "DescribeAlbs", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("ALB DescribeAlbs error", zap.Error(err))
					return err
				}

				response := slb.NewDescribeAlbsResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("ALB DescribeAlbsResponse decode error", zap.Error(err))
					return err
				}
				if len(response.ApplicationLoadBalancerSet) == 0 {
					break
				}

				for i := range response.ApplicationLoadBalancerSet {
					item := &response.ApplicationLoadBalancerSet[i]
					res <- &KSyunALBDetail{
						ALB:       item,
						Listeners: getAlbListeners(ctx, cli, item.AlbId),
					}
				}
				if len(response.ApplicationLoadBalancerSet) < *request.MaxResults {
					break
				}
				request.NextToken = response.NextToken
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.ALB.AlbId",
			ResourceName: "$.ALB.AlbName",
			Address:      "$.ALB.PublicIp",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-central-1",    // 华中1（武汉）
			"cn-hongkong-2",   // 香港
			"ap-singapore-1",  // 新加坡
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

func getAlbListeners(ctx context.Context, cli *slb.Client, lbId *string) (listeners []*ListenerDetail) {
	request := slb.NewDescribeAlbListenersRequest()
	request.MaxResults = common.IntPtr(100)
	request.Filter = []*slb.DescribeAlbListenersFilter{
		1: {
			Name:  common.StringPtr("AlbId"),
			Value: []*string{1: lbId},
		},
	}

	for {
		responseStr := cli.DescribeAlbListenersWithContext(ctx, request)
		collector.ShowResponse(ctx, "ALB", "DescribeAlbListeners", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("ALB DescribeAlbListeners error", zap.Error(err))
			return listeners
		}

		response := slb.NewDescribeAlbListenersResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("ALB DescribeAlbListenersResponse decode error", zap.Error(err))
			return
		}
		localResp := &DescribeListenersResponse{}
		_ = json.Unmarshal([]byte(responseStr), localResp)
		if len(response.AlbListenerSet) == 0 || len(localResp.AlbListenerSet) == 0 || len(response.AlbListenerSet) != len(localResp.AlbListenerSet) {
			return
		}

		for i := range response.AlbListenerSet {
			listeners = append(listeners, &ListenerDetail{
				Listener: &localResp.AlbListenerSet[i],
				Acls:     describeAlbAcls(ctx, cli, response.AlbListenerSet[i].AlbListenerAclId),
			})
		}
		if response.NextToken == nil || len(response.AlbListenerSet) < *request.MaxResults {
			break
		}

		request.NextToken = response.NextToken
	}
	return
}

func describeAlbAcls(ctx context.Context, cli *slb.Client, aclId *string) (acls []any) {
	request := slb.NewDescribeLoadBalancerAclsRequest()
	request.MaxResults = common.IntPtr(100)
	request.LoadBalancerAclId = []*string{
		1: aclId,
	}

	for {
		responseStr := cli.DescribeLoadBalancerAclsWithContext(ctx, request)
		collector.ShowResponse(ctx, "ALB", "DescribeLoadBalancerAcls", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("ALB DescribeLoadBalancerAcls error", zap.Error(err))
			return acls
		}

		response := slb.NewDescribeLoadBalancerAclsResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("ALB DescribeLoadBalancerAclsResponse decode error", zap.Error(err))
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
