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

package computeengine

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"fmt"
	"github.com/cloudrec/gcp/collector"
	"github.com/cloudrec/gcp/utils"
	"go.uber.org/zap"
	"google.golang.org/api/compute/v1"
)

func GetAddressResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.Address,
		ResourceTypeName:  collector.Address,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.google.com/compute/docs/reference/rest/v1/addresses#Address`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			projects := service.(*collector.Services).Projects
			svc := service.(*collector.Services).ComputeService

			for _, project := range projects {
				projectId := project.ProjectId
				loadBalanceDict := LoadBalanceDict{}
				loadBalanceDict.getAllDict(ctx, svc, projectId)

				resp := svc.Addresses.AggregatedList(projectId).MaxResults(100)
				if err := resp.Pages(ctx, func(page *compute.AddressAggregatedList) error {
					for _, item := range page.Items {
						for _, address := range item.Addresses {
							detail := buildAddressDetail(address, &loadBalanceDict)
							res <- detail
						}
					}
					return nil
				}); err != nil {
					log.CtxLogger(ctx).Warn("GetAddressResource error", zap.Error(err))
					continue
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Address.id",
			ResourceName: "$.Address.name",
			Address:      "$.Address.address",
		},
		Dimension: schema.Global,
	}
}

type AddressDetail struct {
	Address            *compute.Address
	ForwardingRules    []*compute.ForwardingRule
	TargetHttpProxies  []*compute.TargetHttpProxy
	TargetHttpsProxies []*compute.TargetHttpsProxy
	TargetTcpProxies   []*compute.TargetTcpProxy
	TargetSslProxies   []*compute.TargetSslProxy
	UrlMaps            []*compute.UrlMap
	BackendServices    []*compute.BackendService
	SecurityPolicies   []*compute.SecurityPolicy
}

type LoadBalanceDict struct {
	// 1. for call function
	ctx       context.Context
	svc       *compute.Service
	projectId string

	// 2. useful dict
	forwardingRulesDict    map[string]*compute.ForwardingRule
	targetHttpProxiesDict  map[string]*compute.TargetHttpProxy
	targetHttpsProxiesDict map[string]*compute.TargetHttpsProxy
	targetTcpProxiesDict   map[string]*compute.TargetTcpProxy
	targetSslProxiesDict   map[string]*compute.TargetSslProxy
	urlMapDict             map[string]*compute.UrlMap
	backendServiceDict     map[string]*compute.BackendService
	securityPolicyDict     map[string]*compute.SecurityPolicy
}

func (d *LoadBalanceDict) getAllDict(ctx context.Context, svc *compute.Service, projectId string) {

	// 1. init
	d.ctx = ctx
	d.svc = svc
	d.projectId = projectId
	d.forwardingRulesDict = make(map[string]*compute.ForwardingRule)
	d.targetHttpProxiesDict = make(map[string]*compute.TargetHttpProxy)
	d.targetHttpsProxiesDict = make(map[string]*compute.TargetHttpsProxy)
	d.targetTcpProxiesDict = make(map[string]*compute.TargetTcpProxy)
	d.targetSslProxiesDict = make(map[string]*compute.TargetSslProxy)
	d.urlMapDict = make(map[string]*compute.UrlMap)
	d.backendServiceDict = make(map[string]*compute.BackendService)
	d.securityPolicyDict = make(map[string]*compute.SecurityPolicy)

	// 2. get all dict
	d.getAllForwardingRules()
	d.getAllTargetHttpProxies()
	d.getAllTargetHttpsProxies()
	d.getAllTargetTcpProxies()
	d.getAllTargetSslProxies()
	d.getAllUrlMaps()
	d.getAllBackendServices()
	d.getAllSecurityPolicies()
}

func (d *LoadBalanceDict) getAllForwardingRules() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	forwardingRulesResp := svc.ForwardingRules.AggregatedList(projectId).MaxResults(100)
	if _err := forwardingRulesResp.Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for _, item := range page.Items {
			for _, forwardingRule := range item.ForwardingRules {
				d.forwardingRulesDict[forwardingRule.Name] = forwardingRule
			}
		}
		return nil
	}); _err != nil {
		return
	}
}

func (d *LoadBalanceDict) getAllTargetHttpProxies() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	targetHttpProxiesResp := svc.TargetHttpProxies.AggregatedList(projectId).MaxResults(100)
	if _err := targetHttpProxiesResp.Pages(ctx, func(page *compute.TargetHttpProxyAggregatedList) error {
		for _, item := range page.Items {
			for _, targetHttpProxy := range item.TargetHttpProxies {
				d.targetHttpProxiesDict[targetHttpProxy.Name] = targetHttpProxy
			}
		}
		return nil
	}); _err != nil {
		return
	}
}

func (d *LoadBalanceDict) getAllTargetHttpsProxies() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	targetHttpsProxiesResp := svc.TargetHttpsProxies.AggregatedList(projectId).MaxResults(100)
	if _err := targetHttpsProxiesResp.Pages(ctx, func(page *compute.TargetHttpsProxyAggregatedList) error {
		for _, item := range page.Items {
			for _, targetHttpsProxy := range item.TargetHttpsProxies {
				d.targetHttpsProxiesDict[targetHttpsProxy.Name] = targetHttpsProxy
			}
		}
		return nil
	}); _err != nil {
		return
	}
}

func (d *LoadBalanceDict) getAllTargetTcpProxies() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	targetTcpProxiesResp := svc.TargetTcpProxies.AggregatedList(projectId).MaxResults(100)
	if _err := targetTcpProxiesResp.Pages(ctx, func(page *compute.TargetTcpProxyAggregatedList) error {
		for _, item := range page.Items {
			for _, targetTcpProxy := range item.TargetTcpProxies {
				d.targetTcpProxiesDict[targetTcpProxy.Name] = targetTcpProxy
			}
		}
		return nil
	}); _err != nil {
		return
	}
}

func (d *LoadBalanceDict) getAllTargetSslProxies() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	targetSslProxiesResp := svc.TargetSslProxies.List(projectId).MaxResults(100)
	if _err := targetSslProxiesResp.Pages(ctx, func(page *compute.TargetSslProxyList) error {
		for _, item := range page.Items {
			d.targetSslProxiesDict[item.Name] = item
		}
		return nil
	}); _err != nil {
		return
	}
}

func (d *LoadBalanceDict) getAllUrlMaps() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	urlMapsResp := svc.UrlMaps.AggregatedList(projectId).MaxResults(100)
	if _err := urlMapsResp.Pages(ctx, func(page *compute.UrlMapsAggregatedList) error {
		for _, item := range page.Items {
			for _, urlMap := range item.UrlMaps {
				d.urlMapDict[urlMap.Name] = urlMap
			}
		}
		return nil
	}); _err != nil {
		return
	}
}

func (d *LoadBalanceDict) getAllBackendServices() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	backendServicesResp := svc.BackendServices.AggregatedList(projectId).MaxResults(100)
	if _err := backendServicesResp.Pages(ctx, func(page *compute.BackendServiceAggregatedList) error {
		for _, item := range page.Items {
			for _, backendService := range item.BackendServices {
				d.backendServiceDict[backendService.Name] = backendService
			}
		}
		return nil
	}); _err != nil {
		return
	}
}

func (d *LoadBalanceDict) getAllSecurityPolicies() {

	ctx := d.ctx
	svc := d.svc
	projectId := d.projectId

	securityPoliciesResp := svc.SecurityPolicies.AggregatedList(projectId).MaxResults(100)
	if _err := securityPoliciesResp.Pages(ctx, func(page *compute.SecurityPoliciesAggregatedList) error {
		for _, item := range page.Items {
			for _, securityPolicy := range item.SecurityPolicies {
				d.securityPolicyDict[securityPolicy.Name] = securityPolicy
			}
		}
		return nil
	}); _err != nil {
		return
	}
}

func buildAddressDetail(address *compute.Address, loadBalanceDict *LoadBalanceDict) (detail *AddressDetail) {

	detail = &AddressDetail{
		Address:            address,
		ForwardingRules:    make([]*compute.ForwardingRule, 0),
		TargetHttpProxies:  make([]*compute.TargetHttpProxy, 0),
		TargetHttpsProxies: make([]*compute.TargetHttpsProxy, 0),
		TargetTcpProxies:   make([]*compute.TargetTcpProxy, 0),
		TargetSslProxies:   make([]*compute.TargetSslProxy, 0),
		UrlMaps:            make([]*compute.UrlMap, 0),
		BackendServices:    make([]*compute.BackendService, 0),
		SecurityPolicies:   make([]*compute.SecurityPolicy, 0),
	}

	// address.Users would be a list
	for _, user := range address.Users {
		rType := utils.GetResourceType(user)
		rId := utils.GetResourceID(user)
		switch rType {
		case "forwardingRules":
			forwardingRule := loadBalanceDict.forwardingRulesDict[rId]
			forwardingRuleTargetType := utils.GetResourceType(forwardingRule.Target)
			forwardingRuleTargetId := utils.GetResourceID(forwardingRule.Target)

			switch forwardingRuleTargetType {

			// 1. Application Load Balancers
			// [Traffic] --> [Forwarding Rule] --> [Target HTTP/HTTPS proxy] --> [URL Map] --> [Backend Service]
			// todo: there are too many place to set service T^T
			case "targetHttpProxies":
				fmt.Println("No Support")
				continue
			case "targetHttpsProxies":
				fmt.Println("No Support")
				continue

			// 2 Proxy Network Load Balancers
			//	[Traffic] --> [Forwarding Rule] --> [Target TCP/SSL proxy] --> [Backend Service]
			case "targetTcpProxies":
				tmpTargetTcpProxy := loadBalanceDict.targetTcpProxiesDict[forwardingRuleTargetId]
				tmpBackendService := loadBalanceDict.backendServiceDict[utils.GetResourceID(tmpTargetTcpProxy.Service)]
				tmpSecurityPolicy := loadBalanceDict.securityPolicyDict[utils.GetResourceID(tmpBackendService.SecurityPolicy)]

				detail.ForwardingRules = append(detail.ForwardingRules, forwardingRule)
				detail.TargetTcpProxies = append(detail.TargetTcpProxies, tmpTargetTcpProxy)
				detail.BackendServices = append(detail.BackendServices, tmpBackendService)
				detail.SecurityPolicies = append(detail.SecurityPolicies, tmpSecurityPolicy)
			case "targetSslProxies":
				tmpTargetSslProxy := loadBalanceDict.targetSslProxiesDict[forwardingRuleTargetId]
				tmpBackendService := loadBalanceDict.backendServiceDict[utils.GetResourceID(tmpTargetSslProxy.Service)]
				tmpSecurityPolicy := loadBalanceDict.securityPolicyDict[utils.GetResourceID(tmpBackendService.SecurityPolicy)]

				detail.ForwardingRules = append(detail.ForwardingRules, forwardingRule)
				detail.TargetSslProxies = append(detail.TargetSslProxies, tmpTargetSslProxy)
				detail.BackendServices = append(detail.BackendServices, tmpBackendService)
				detail.SecurityPolicies = append(detail.SecurityPolicies, tmpSecurityPolicy)

			// 3. Passthrough Network Load Balancers
			// [Traffic] --> [Forwarding Rule] --> [Backend Service]
			case "backendServices":
				tmpBackendService := loadBalanceDict.backendServiceDict[forwardingRuleTargetId]
				tmpSecurityPolicy := loadBalanceDict.securityPolicyDict[utils.GetResourceID(tmpBackendService.SecurityPolicy)]

				detail.ForwardingRules = append(detail.ForwardingRules, forwardingRule)
				detail.BackendServices = append(detail.BackendServices, tmpBackendService)
				detail.SecurityPolicies = append(detail.SecurityPolicies, tmpSecurityPolicy)
			// 4. Other use case
			default:
				fmt.Println("Unknown ForwardingRule Target Type")
				continue
			}

		default:
			fmt.Println("Unknown Address User Type")
			continue
		}

	}

	return
}
