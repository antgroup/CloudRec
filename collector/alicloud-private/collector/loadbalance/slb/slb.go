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
	"github.com/alicloud-sqa/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/slb"
	"go.uber.org/zap"
	"strconv"
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
	LoadBalancer          slb.LoadBalancer
	LoadBalancerAttribute *slb.DescribeLoadBalancerAttributeResponse
	Listeners             []*ListenerDetail
}

type ListenerDetail struct {
	Listener slb.ListenerInDescribeLoadBalancerListeners
	Acl      *slb.DescribeAccessControlListAttributeResponse
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	svc := service.(*collector.Services)
	req := slb.CreateDescribeLoadBalancersRequest()
	req.PageSize = requests.NewInteger(constant.DefaultPageSize)
	req.PageNumber = requests.NewInteger(constant.DefaultPage)
	req.Scheme = "HTTPS"
	req.QueryParams["product"] = "SLB"
	req.SetHTTPSInsecure(true)
	count := 0
	for {
		resp, err := svc.SlbClient.DescribeLoadBalancers(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
			return err
		}

		count += len(resp.LoadBalancers.LoadBalancer)
		for i := 0; i < len(resp.LoadBalancers.LoadBalancer); i++ {
			d := &Detail{
				LoadBalancer:          resp.LoadBalancers.LoadBalancer[i],
				LoadBalancerAttribute: describeLoadBalancerAttribute(ctx, svc.SlbClient, resp.LoadBalancers.LoadBalancer[i].LoadBalancerId),
				Listeners:             listListeners(ctx, svc.SlbClient, resp.LoadBalancers.LoadBalancer[i].LoadBalancerId, "", ""),
			}

			if d.LoadBalancerAttribute == nil {
				d.LoadBalancerAttribute, d.Listeners = describeWithResourceGroup(ctx, svc.SlbClient, resp.LoadBalancers.LoadBalancer[i].LoadBalancerId, svc.ResourceGroups)
			}

			res <- d
		}

		if count >= resp.TotalCount || len(resp.LoadBalancers.LoadBalancer) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}
	return nil
}

func describeLoadBalancerAttribute(ctx context.Context, client *slb.Client, loadBalancerId string) (response *slb.DescribeLoadBalancerAttributeResponse) {
	req := slb.CreateDescribeLoadBalancerAttributeRequest()
	req.Scheme = "HTTPS"
	req.QueryParams["product"] = "SLB"
	req.SetHTTPSInsecure(true)
	req.LoadBalancerId = loadBalancerId
	resp, err := client.DescribeLoadBalancerAttribute(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLoadBalancerAttribute error", zap.Error(err))
		return
	}

	return resp
}

// env SQA or UAT SLB attributes detail requires distinguishing between resourceGroups
func describeWithResourceGroup(ctx context.Context, client *slb.Client, loadBalancerId string, resourceGroups []collector.ResourceGroup) (response *slb.DescribeLoadBalancerAttributeResponse, Listeners []*ListenerDetail) {
	req := slb.CreateDescribeLoadBalancerAttributeRequest()
	req.Scheme = "HTTPS"
	req.QueryParams["product"] = "SLB"
	req.SetHTTPSInsecure(true)
	req.LoadBalancerId = loadBalancerId

	// env SQA need this, env UAT dont
	for _, r := range resourceGroups {
		req.Headers["x-acs-organizationId"] = strconv.Itoa(int(r.OrganizationID))
		req.Headers["x-acs-resourceGroupId"] = strconv.Itoa(int(r.Id))
		resp, err := client.DescribeLoadBalancerAttribute(req)
		if err != nil {
			continue
		}

		log.CtxLogger(ctx).Info(fmt.Sprintf("loadBalancerId %s describeLoadBalancerAttributeWhitResourceGroup success", loadBalancerId))
		listeners := listListeners(ctx, client, loadBalancerId, strconv.Itoa(int(r.OrganizationID)), strconv.Itoa(int(r.Id)))
		return resp, listeners
	}

	return nil, nil

}

func listListeners(ctx context.Context, client *slb.Client, loadBalancerId string, organizationId string, resourceGroupId string) (Listeners []*ListenerDetail) {
	request := slb.CreateDescribeLoadBalancerListenersRequest()
	if organizationId != "" {
		request.Headers["x-acs-organizationId"] = organizationId
	}
	if resourceGroupId != "" {
		request.Headers["x-acs-resourceGroupId"] = resourceGroupId
	}

	loadBalancerIds := []string{loadBalancerId}
	request.LoadBalancerId = &loadBalancerIds
	request.Scheme = "HTTPS"
	request.QueryParams["product"] = "SLB"
	request.SetHTTPSInsecure(true)
	count := 0
	for {
		resp, err := client.DescribeLoadBalancerListeners(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeLoadBalancerListeners error", zap.Error(err))
			break
		}
		log.CtxLogger(ctx).Info(fmt.Sprintf("loadBalancerId %s DescribeLoadBalancerListeners resp,Listener count %d", loadBalancerId, resp.TotalCount))

		for i := 0; i < len(resp.Listeners); i++ {
			ld := &ListenerDetail{
				Listener: resp.Listeners[i],
				Acl:      describeAccessControlListAttribute(ctx, client, resp.Listeners[i].AclId, organizationId, resourceGroupId),
			}

			log.CtxLogger(ctx).Info(fmt.Sprintf("loadBalancerId %s listListeners success", loadBalancerId))
			Listeners = append(Listeners, ld)
		}

		count += len(resp.Listeners)
		if count >= resp.TotalCount || len(resp.Listeners) == 0 || resp.NextToken == "" {
			break
		}
		request.NextToken = resp.NextToken
	}

	return
}

func describeAccessControlListAttribute(ctx context.Context, client *slb.Client, aclId string, organizationId string, resourceGroupId string) (acl *slb.DescribeAccessControlListAttributeResponse) {
	if aclId == "" {
		return
	}
	req := slb.CreateDescribeAccessControlListAttributeRequest()
	req.Headers["x-acs-organizationId"] = organizationId
	req.Headers["x-acs-resourceGroupId"] = resourceGroupId
	req.Scheme = "HTTPS"
	req.QueryParams["product"] = "SLB"
	req.SetHTTPSInsecure(true)
	req.AclId = aclId
	resp, err := client.DescribeAccessControlListAttribute(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAccessControlListAttribute error", zap.Error(err))
		return
	}

	log.CtxLogger(ctx).Info(fmt.Sprintf("aclId %s DescribeAccessControlListAttribute success", aclId))

	return resp
}
