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
	"net"
	"time"

	slb20140515 "github.com/alibabacloud-go/slb-20140515/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetSLBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SLB,
		ResourceTypeName:   collector.SLB,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Slb`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.LoadBalancer.LoadBalancerId",
			ResourceName: "$.LoadBalancer.LoadBalancerName",
			Address:      "$.LoadBalancer.Address",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {

	// basic info
	LoadBalancer *slb20140515.DescribeLoadBalancersResponseBodyLoadBalancersLoadBalancer
	// detailed attribute
	LoadBalancerAttribute *slb20140515.DescribeLoadBalancerAttributeResponseBody
	Listeners             []*ListenerDetail

	EipAddress []vpc.EipAddress
}

type ListenerDetail struct {
	Listener *slb20140515.DescribeLoadBalancerListenersResponseBodyListeners
	AclList  []*slb20140515.DescribeAccessControlListAttributeResponseBody
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	svc := service.(*collector.Services)
	config := svc.Config
	cli := svc.SLB
	cli.RegionId = config.RegionId
	isSpeedEndpoint := false
	req := &slb20140515.DescribeLoadBalancersRequest{}
	req.PageSize = tea.ToInt32(tea.Int(constant.DefaultPageSize))
	req.PageNumber = tea.ToInt32(tea.Int(constant.DefaultPage))
	req.RegionId = config.RegionId
	count := 0
	for {
		resp, err := cli.DescribeLoadBalancersWithOptions(req, collector.RuntimeObject)
		if err != nil {
			if _, ok := err.(net.Error); ok && !isSpeedEndpoint {
				isSpeedEndpoint = true
				cli.Endpoint = &slbSpeedEndpoint
				continue
			}
			log.CtxLogger(ctx).Warn("DescribeLoadBalancers err: %s", zap.Error(err))
			break
		}

		count += len(resp.Body.LoadBalancers.LoadBalancer)
		for _, lb := range resp.Body.LoadBalancers.LoadBalancer {
			d := &Detail{
				LoadBalancer:          lb,
				LoadBalancerAttribute: describeLoadBalancerAttribute(ctx, cli, lb.LoadBalancerId),
				Listeners:             listListeners(ctx, cli, lb.LoadBalancerId),
				EipAddress:            describeEipAddress(ctx, svc, lb.LoadBalancerId),
			}
			res <- d
		}

		if count >= int(*resp.Body.TotalCount) || len(resp.Body.LoadBalancers.LoadBalancer) == 0 {
			break
		}
		*req.PageNumber = *resp.Body.PageNumber + 1
	}

	return nil
}

var slbSpeedEndpoint = "slb.aliyuncs.com"

func describeEipAddress(ctx context.Context, svc schema.ServiceInterface, id *string) []vpc.EipAddress {
	req := vpc.CreateDescribeEipAddressesRequest()
	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	req.AssociatedInstanceId = *id
	resp, err := svc.(*collector.Services).VPC.DescribeEipAddresses(req)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeEipAddresses error", zap.Error(err))
		return nil
	}
	return resp.EipAddresses.EipAddress
}

func describeLoadBalancerAttribute(ctx context.Context, cli *slb20140515.Client, loadBalancerId *string) (Body *slb20140515.DescribeLoadBalancerAttributeResponseBody) {
	req := &slb20140515.DescribeLoadBalancerAttributeRequest{}
	req.LoadBalancerId = loadBalancerId
	resp, err := cli.DescribeLoadBalancerAttribute(req)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeLoadBalancerAttribute error", zap.Error(err))
		return
	}

	return resp.Body
}

func listListeners(ctx context.Context, cli *slb20140515.Client, loadBalancerId *string) (listeners []*ListenerDetail) {
	request := &slb20140515.DescribeLoadBalancerListenersRequest{
		LoadBalancerId: []*string{loadBalancerId},
		RegionId:       cli.RegionId,
	}
	count := 0
	for {
		resp, err := cli.DescribeLoadBalancerListeners(request)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeLoadBalancerListeners error", zap.Error(err))
			return
		}
		count += len(resp.Body.Listeners)
		for _, li := range resp.Body.Listeners {
			ld := &ListenerDetail{
				Listener: li,
				AclList:  describeAccessControlListAttribute(ctx, cli, li.AclIds),
			}
			listeners = append(listeners, ld)
		}

		if count >= int(*resp.Body.TotalCount) || len(resp.Body.Listeners) == 0 {
			break
		}
		request.NextToken = resp.Body.NextToken
	}
	time.Sleep(200)

	return listeners
}

func describeAccessControlListAttribute(ctx context.Context, client *slb20140515.Client, aclIds []*string) (aclList []*slb20140515.DescribeAccessControlListAttributeResponseBody) {
	for _, id := range aclIds {
		req := &slb20140515.DescribeAccessControlListAttributeRequest{
			AclId:    id,
			RegionId: client.RegionId,
		}
		resp, err := client.DescribeAccessControlListAttribute(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeAccessControlListAttribute error", zap.Error(err))
			return
		}

		aclList = append(aclList, resp.Body)
	}

	return aclList
}
