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
	alb20200616 "github.com/alibabacloud-go/alb-20200616/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"time"
)

func GetALBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ALB,
		ResourceTypeName:   collector.ALB,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Alb`,
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
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ALB

	request := &alb20200616.ListLoadBalancersRequest{}
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

type Detail struct {
	RegionId string

	Endpoint *string
	// basic info
	LoadBalancer *alb20200616.ListLoadBalancersResponseBodyLoadBalancers
	// detailed attribute
	LoadBalancerAttribute *alb20200616.GetLoadBalancerAttributeResponseBody
	Listeners             []*ListenerDetail
}

type ListenerDetail struct {
	Listener          *alb20200616.ListListenersResponseBodyListeners
	ListenerAttribute ListenerAttribute
}

type ListenerAttribute struct {
	ListenerAttributeDetail *alb20200616.GetListenerAttributeResponseBody
	AclList                 []*AclDetail
}

type AclDetail struct {
	AclId      *string
	AclType    *string
	AclEntries []*alb20200616.ListAclEntriesResponseBodyAclEntries
}

func getLoadBalancerAttribute(ctx context.Context, cli *alb20200616.Client, loadBalancerId *string) (Body *alb20200616.GetLoadBalancerAttributeResponseBody) {
	request := &alb20200616.GetLoadBalancerAttributeRequest{}
	request.LoadBalancerId = loadBalancerId
	resp, err := cli.GetLoadBalancerAttributeWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("GetLoadBalancerAttributeWithOptions error", zap.Error(err))
		return
	}

	return resp.Body
}

func listListeners(ctx context.Context, cli *alb20200616.Client, loadBalancerId *string) (listeners []*ListenerDetail) {
	request := &alb20200616.ListListenersRequest{}
	request.LoadBalancerIds = []*string{loadBalancerId}
	count := 0
	for {
		resp, err := cli.ListListenersWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Error("ListListenersWithOptions error", zap.Error(err))
			return
		}
		count += len(resp.Body.Listeners)
		for i := 0; i < len(resp.Body.Listeners); i++ {
			// query listener detailed attribute
			listenerAttribute := getListenerAttribute(ctx, collector.RuntimeObject, cli, resp.Body.Listeners[i].ListenerId)

			// query listener acl list
			var aclList []*AclDetail
			if listenerAttribute.AclConfig != nil {
				for _, acl := range listenerAttribute.AclConfig.AclRelations {
					aclDetail := &AclDetail{
						AclId:      acl.AclId,
						AclType:    listenerAttribute.AclConfig.AclType,
						AclEntries: listAclEntries(ctx, collector.RuntimeObject, cli, acl.AclId),
					}
					aclList = append(aclList, aclDetail)
				}
			}

			ld := &ListenerDetail{
				Listener: resp.Body.Listeners[i],
				ListenerAttribute: ListenerAttribute{
					ListenerAttributeDetail: listenerAttribute,
					AclList:                 aclList,
				},
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

func getListenerAttribute(ctx context.Context, runtime *util.RuntimeOptions, client *alb20200616.Client, listenerId *string) (body *alb20200616.GetListenerAttributeResponseBody) {
	request := &alb20200616.GetListenerAttributeRequest{
		ListenerId: listenerId,
	}

	resp, err := client.GetListenerAttributeWithOptions(request, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("GetListenerAttributeWithOptions error", zap.Error(err))
		return
	}

	return resp.Body
}

func listAclEntries(ctx context.Context, runtime *util.RuntimeOptions, client *alb20200616.Client, aclId *string) (aclEntries []*alb20200616.ListAclEntriesResponseBodyAclEntries) {
	request := &alb20200616.ListAclEntriesRequest{
		AclId: aclId,
	}

	count := 0
	for {
		resp, err := client.ListAclEntriesWithOptions(request, runtime)
		if err != nil {
			log.CtxLogger(ctx).Error("ListAclEntriesWithOptions error", zap.Error(err))
			return
		}
		aclEntries = append(aclEntries, resp.Body.AclEntries...)
		count += len(resp.Body.AclEntries)
		if count >= int(tea.Int32Value(resp.Body.TotalCount)) || len(resp.Body.AclEntries) == 0 {
			break
		}
		time.Sleep(200)
		request.NextToken = resp.Body.NextToken
	}
	return aclEntries
}
