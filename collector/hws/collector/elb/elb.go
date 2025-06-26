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

package elb

import (
	"context"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/cloudrec/hws/collector"
	elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/model"
	"go.uber.org/zap"
)

func GetELBInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ELB,
		ResourceTypeName:   "ELB",
		ResourceGroupType:  constant.NET,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/ELB/debug?api=ListApiVersions&version=v3",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.LoadBalancer.id",
			ResourceName: "$.LoadBalancer.name",
		},
		Dimension: schema.Regional,
	}
}

type InstanceDetail struct {
	LoadBalancer    model.LoadBalancer
	Members         *[]model.Member
	IpGroupsDetails []*IpGroupsDetail
	ListenerDetails []*model.Listener
}

type IpGroupsDetail struct {
	ListenerId string           `json:"listenerId"`
	IpGroups   *[]model.IpGroup `json:"IpGroups"`
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ELB
	limit := int32(50)
	request := &model.ListLoadBalancersRequest{
		Limit: &limit,
	}
	for {
		response, err := cli.ListLoadBalancers(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListLoadBalancers error", zap.Error(err))
			return err
		}

		for _, lb := range *response.Loadbalancers {
			res <- buildDetail(ctx, cli, lb)
		}

		if len(*response.Loadbalancers) < int(limit) {
			break
		}

		loadbalancers := (*response.Loadbalancers)[len(*response.Loadbalancers)-1]

		request.Marker = &loadbalancers.Id
	}
	return nil
}

func buildDetail(ctx context.Context, cli *elb.ElbClient, loadBalancer model.LoadBalancer) (detail InstanceDetail) {
	return InstanceDetail{
		LoadBalancer:    loadBalancer,
		Members:         listMembers(ctx, cli, loadBalancer),
		IpGroupsDetails: listIpGroups(ctx, cli, loadBalancer),
		ListenerDetails: listListerner(ctx, cli, loadBalancer),
	}
}

func listMembers(ctx context.Context, cli *elb.ElbClient, loadBalancer model.LoadBalancer) (res *[]model.Member) {
	for _, pool := range loadBalancer.Pools {
		response, err := cli.ListMembers(&model.ListMembersRequest{
			PoolId: pool.Id,
		})
		if err != nil {
			log.CtxLogger(ctx).Warn("ListMembers error", zap.Error(err))
			return
		} else {
			return response.Members
		}
	}
	return
}

func listIpGroups(ctx context.Context, cli *elb.ElbClient, loadBalancer model.LoadBalancer) (res []*IpGroupsDetail) {
	var ipGroups []model.IpGroup
	request := &model.ListIpGroupsRequest{}
	limit := int32(100)
	for {
		response, err := cli.ListIpGroups(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListIpGroups error", zap.Error(err))
			return
		}

		ipGroups = append(ipGroups, *response.Ipgroups...)
		if len(*response.Ipgroups) < int(limit) {
			break
		}

		whiteListResp := (*response.Ipgroups)[len(*response.Ipgroups)-1]

		request.Marker = &whiteListResp.Id
	}

	for _, listener := range loadBalancer.Listeners {
		for _, ipGroup := range ipGroups {
			for _, ipGroupListener := range ipGroup.Listeners {
				if listener.Id == ipGroupListener.Id {
					res = append(res, &IpGroupsDetail{
						ListenerId: listener.Id,
						IpGroups:   &[]model.IpGroup{ipGroup},
					})
				}
			}
		}
	}
	return
}

func listListerner(ctx context.Context, cli *elb.ElbClient, loadBalancer model.LoadBalancer) (res []*model.Listener) {
	request := &model.ShowListenerRequest{}
	for _, listener := range loadBalancer.Listeners {
		request.ListenerId = listener.Id
		response, err := cli.ShowListener(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ShowListener error", zap.Error(err))
			return nil
		}
		res = append(res, response.Listener)
	}
	return res
}
