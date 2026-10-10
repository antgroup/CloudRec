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

				// List the addresses before building the load balancer dictionary.
				// getAllDict costs eight AggregatedList calls per project, and in an
				// org-wide scan the overwhelming majority of projects hold no address
				// at all, so paying that up front is what pushes the whole resource
				// type past its context deadline.
				addresses := make([]*compute.Address, 0)
				resp := svc.Addresses.AggregatedList(projectId).MaxResults(100)
				if err := resp.Pages(ctx, func(page *compute.AddressAggregatedList) error {
					for _, item := range page.Items {
						addresses = append(addresses, item.Addresses...)
					}
					return nil
				}); err != nil {
					log.CtxLogger(ctx).Warn("GetAddressResource error", zap.Error(err))
					continue
				}
				if len(addresses) == 0 {
					continue
				}

				loadBalanceDict := LoadBalanceDict{}
				loadBalanceDict.getAllDict(ctx, svc, projectId)

				for _, address := range addresses {
					res <- buildAddressDetail(ctx, address, &loadBalanceDict)
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
		log.CtxLogger(ctx).Warn("getAllForwardingRules error", zap.Error(_err))
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
		log.CtxLogger(ctx).Warn("getAllTargetHttpProxies error", zap.Error(_err))
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
		log.CtxLogger(ctx).Warn("getAllTargetHttpsProxies error", zap.Error(_err))
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
		log.CtxLogger(ctx).Warn("getAllTargetTcpProxies error", zap.Error(_err))
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
		log.CtxLogger(ctx).Warn("getAllTargetSslProxies error", zap.Error(_err))
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
		log.CtxLogger(ctx).Warn("getAllUrlMaps error", zap.Error(_err))
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
		log.CtxLogger(ctx).Warn("getAllBackendServices error", zap.Error(_err))
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
		log.CtxLogger(ctx).Warn("getAllSecurityPolicies error", zap.Error(_err))
		return
	}
}

func buildAddressDetail(ctx context.Context, address *compute.Address, loadBalanceDict *LoadBalanceDict) (detail *AddressDetail) {

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
			// Every lookup below can miss: the dictionary is assembled from a
			// separate set of AggregatedList calls, any of which may have failed
			// or been truncated. A map miss yields a nil pointer, so it must be
			// checked before use rather than dereferenced.
			forwardingRule := loadBalanceDict.forwardingRulesDict[rId]
			if forwardingRule == nil {
				log.CtxLogger(ctx).Debug("forwardingRule missing from dict", zap.String("forwardingRule", rId))
				continue
			}
			forwardingRuleTargetType := utils.GetResourceType(forwardingRule.Target)
			forwardingRuleTargetId := utils.GetResourceID(forwardingRule.Target)

			switch forwardingRuleTargetType {

			// 1. Application Load Balancers
			// [Traffic] --> [Forwarding Rule] --> [Target HTTP/HTTPS proxy] --> [URL Map] --> [Backend Service]
			// todo: there are too many place to set service T^T
			case "targetHttpProxies", "targetHttpsProxies":
				log.CtxLogger(ctx).Debug("application load balancer target is not supported yet",
					zap.String("targetType", forwardingRuleTargetType))
				continue

			// 2 Proxy Network Load Balancers
			//	[Traffic] --> [Forwarding Rule] --> [Target TCP/SSL proxy] --> [Backend Service]
			case "targetTcpProxies":
				tmpTargetTcpProxy := loadBalanceDict.targetTcpProxiesDict[forwardingRuleTargetId]
				if tmpTargetTcpProxy == nil {
					log.CtxLogger(ctx).Debug("targetTcpProxy missing from dict", zap.String("targetTcpProxy", forwardingRuleTargetId))
					continue
				}

				detail.ForwardingRules = append(detail.ForwardingRules, forwardingRule)
				detail.TargetTcpProxies = append(detail.TargetTcpProxies, tmpTargetTcpProxy)
				appendBackendService(ctx, detail, loadBalanceDict, utils.GetResourceID(tmpTargetTcpProxy.Service))
			case "targetSslProxies":
				tmpTargetSslProxy := loadBalanceDict.targetSslProxiesDict[forwardingRuleTargetId]
				if tmpTargetSslProxy == nil {
					log.CtxLogger(ctx).Debug("targetSslProxy missing from dict", zap.String("targetSslProxy", forwardingRuleTargetId))
					continue
				}

				detail.ForwardingRules = append(detail.ForwardingRules, forwardingRule)
				detail.TargetSslProxies = append(detail.TargetSslProxies, tmpTargetSslProxy)
				appendBackendService(ctx, detail, loadBalanceDict, utils.GetResourceID(tmpTargetSslProxy.Service))

			// 3. Passthrough Network Load Balancers
			// [Traffic] --> [Forwarding Rule] --> [Backend Service]
			case "backendServices":
				detail.ForwardingRules = append(detail.ForwardingRules, forwardingRule)
				appendBackendService(ctx, detail, loadBalanceDict, forwardingRuleTargetId)
			// 4. Other use case
			default:
				log.CtxLogger(ctx).Debug("unknown forwardingRule target type", zap.String("targetType", forwardingRuleTargetType))
				continue
			}

		default:
			log.CtxLogger(ctx).Debug("unknown address user type", zap.String("userType", rType))
			continue
		}

	}

	return
}

// appendBackendService resolves a backend service and its Cloud Armor policy out
// of the dictionary and appends whatever could be resolved to detail. Entries the
// dictionary cannot resolve are skipped rather than appended as nil, which would
// otherwise put a null into the persisted resource JSON.
func appendBackendService(ctx context.Context, detail *AddressDetail, loadBalanceDict *LoadBalanceDict, backendServiceId string) {
	backendService := loadBalanceDict.backendServiceDict[backendServiceId]
	if backendService == nil {
		log.CtxLogger(ctx).Debug("backendService missing from dict", zap.String("backendService", backendServiceId))
		return
	}
	detail.BackendServices = append(detail.BackendServices, backendService)

	// A backend service with no Cloud Armor policy attached is perfectly normal,
	// so an unresolved policy is not worth reporting.
	securityPolicy := loadBalanceDict.securityPolicyDict[utils.GetResourceID(backendService.SecurityPolicy)]
	if securityPolicy == nil {
		return
	}
	detail.SecurityPolicies = append(detail.SecurityPolicies, securityPolicy)
}
