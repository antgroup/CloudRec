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

package nlb

import (
	"context"
	nlb20220430 "github.com/alibabacloud-go/nlb-20220430/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"time"
)

type Detail struct {
	EndPoint *string
	// basic info
	LoadBalancer *nlb20220430.ListLoadBalancersResponseBodyLoadBalancers
	// detailed attribute
	LoadBalancerAttribute *nlb20220430.GetLoadBalancerAttributeResponseBody
	Listeners             []*ListenerDetail
}

type ListenerDetail struct {
	Listener           *nlb20220430.ListListenersResponseBodyListeners
	ListenerAttribute  *nlb20220430.GetListenerAttributeResponseBody
	ServerGroupServers []*nlb20220430.ListServerGroupServersResponseBodyServers
}

func GetNLBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NLB,
		ResourceTypeName:   collector.NLB,
		ResourceGroupType:  constant.NET,
		Desc:               "https://api.aliyun.com/product/Nlb",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.LoadBalancer.LoadBalancerId",
			ResourceName: "$.LoadBalancer.LoadBalancerName",
			Address:      "$.LoadBalancer.DNSName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-nanjing",
			"cn-fuzhou",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"cn-wuhan-lr",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-zhengzhou-jva",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"na-south-1",
			"eu-west-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).NLB

	request := &nlb20220430.ListLoadBalancersRequest{
		RegionId: cli.RegionId,
	}

	count := 0
	for {
		resp, err := cli.ListLoadBalancersWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Error("ListLoadBalancersWithOptions error", zap.Error(err))
			return err
		}
		count += len(resp.Body.LoadBalancers)
		for _, lb := range resp.Body.LoadBalancers {
			d := &Detail{
				LoadBalancer:          lb,
				LoadBalancerAttribute: getLoadBalancerAttribute(ctx, cli, lb.LoadBalancerId),
				Listeners:             listListeners(ctx, cli, lb.LoadBalancerId),
			}
			res <- d
		}
		if count >= int(tea.Int32Value(resp.Body.TotalCount)) || len(resp.Body.LoadBalancers) == 0 {
			break
		}
		request.NextToken = resp.Body.NextToken
	}

	return nil
}

func getLoadBalancerAttribute(ctx context.Context, cli *nlb20220430.Client, instanceId *string) (Body *nlb20220430.GetLoadBalancerAttributeResponseBody) {
	request := &nlb20220430.GetLoadBalancerAttributeRequest{
		RegionId: cli.RegionId,
	}
	request.LoadBalancerId = instanceId
	resp, err := cli.GetLoadBalancerAttributeWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("GetLoadBalancerAttributeWithOptions error", zap.Error(err))
		return
	}

	return resp.Body
}

func listListeners(ctx context.Context, cli *nlb20220430.Client, instanceId *string) (listeners []*ListenerDetail) {
	request := &nlb20220430.ListListenersRequest{
		RegionId:        cli.RegionId,
		LoadBalancerIds: []*string{instanceId},
	}

	count := 0
	for {
		resp, err := cli.ListListenersWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Error("ListListenersWithOptions error", zap.Error(err))
			break
		}
		count += len(resp.Body.Listeners)
		for i := 0; i < len(resp.Body.Listeners); i++ {

			listenerAttribute := getListenerAttribute(ctx, cli, resp.Body.Listeners[i].ListenerId, cli.RegionId)
			serverGroupServers := listServerGroupServers(ctx, cli, listenerAttribute.ServerGroupId)
			// query listener detailed info
			ld := &ListenerDetail{
				Listener:           resp.Body.Listeners[i],
				ListenerAttribute:  listenerAttribute,
				ServerGroupServers: serverGroupServers,
			}
			listeners = append(listeners, ld)
		}

		if count >= int(tea.Int32Value(resp.Body.TotalCount)) || len(resp.Body.Listeners) == 0 {
			break
		}
		request.NextToken = resp.Body.NextToken
	}
	time.Sleep(200)

	return listeners
}

func listServerGroupServers(ctx context.Context, cli *nlb20220430.Client, id *string) (listServerGroupServers []*nlb20220430.ListServerGroupServersResponseBodyServers) {
	request := &nlb20220430.ListServerGroupServersRequest{
		ServerGroupId: id,
	}
	resp, err := cli.ListServerGroupServers(request)
	if err != nil {
		log.CtxLogger(ctx).Error("ListServerGroupServers error", zap.Error(err))
		return nil
	}
	listServerGroupServers = append(listServerGroupServers, resp.Body.Servers...)
	for resp.Body.NextToken != nil {
		request.NextToken = resp.Body.NextToken
		resp, err = cli.ListServerGroupServers(request)
		if err != nil {
			return nil
		}
		listServerGroupServers = append(listServerGroupServers, resp.Body.Servers...)
	}
	return listServerGroupServers
}

func getListenerAttribute(ctx context.Context, client *nlb20220430.Client, listenerId *string, regionId *string) (body *nlb20220430.GetListenerAttributeResponseBody) {
	request := &nlb20220430.GetListenerAttributeRequest{
		RegionId:   regionId,
		ListenerId: listenerId,
	}

	resp, err := client.GetListenerAttributeWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("GetListenerAttributeWithOptions error", zap.Error(err))
		return
	}

	return resp.Body

}
