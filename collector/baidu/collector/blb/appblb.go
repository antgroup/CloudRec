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

package blb

import (
	"context"
	"strconv"

	"github.com/baidubce/bce-sdk-go/bce"
	"github.com/baidubce/bce-sdk-go/services/appblb"
	"github.com/cloudrec/baidu/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// enrichedAppBLB embeds appblb.AppBLBModel so existing $.AppBLB.* paths stay
// intact; the trailing fields are returned by /v1/appblb but not modeled by
// the baidu SDK's AppBLBModel.
type enrichedAppBLB struct {
	appblb.AppBLBModel
	Type                         string `json:"type"`
	UnderlayVip                  string `json:"underlayVip"`
	ExpireTime                   string `json:"expireTime"`
	BillingMethod                string `json:"billingMethod"`
	PaymentTiming                string `json:"paymentTiming"`
	PerformanceLevel             string `json:"performanceLevel"`
	AllowModify                  bool   `json:"allowModify"`
	ModificationProtectionReason string `json:"modificationProtectionReason"`
}

type enrichedAppListener struct {
	appblb.AppAllListenerModel
	Description string `json:"description"`
}

type enrichedAppServerGroupPort struct {
	appblb.AppServerGroupPort
	HealthCheckValid int `json:"healthCheckValid"`
}

// enrichedAppServerGroup mirrors appblb.AppServerGroup but swaps in
// enrichedAppServerGroupPort so the missing portList[].healthCheckValid
// is preserved. Fields kept verbatim from the SDK type.
type enrichedAppServerGroup struct {
	Id          string                       `json:"id"`
	Name        string                       `json:"name"`
	Description string                       `json:"desc"`
	Status      appblb.BLBStatus             `json:"status"`
	PortList    []enrichedAppServerGroupPort `json:"portList"`
}

type enrichedDescribeAppLoadBalancersResult struct {
	BlbList []enrichedAppBLB `json:"blbList"`
	appblb.DescribeResultMeta
}

type enrichedDescribeAppAllListenersResult struct {
	ListenerList []enrichedAppListener `json:"listenerList"`
	appblb.DescribeResultMeta
}

type enrichedDescribeAppServerGroupResult struct {
	AppServerGroupList []enrichedAppServerGroup `json:"appServerGroupList"`
	appblb.DescribeResultMeta
}

type AppBLBDetail struct {
	AppBLB                   enrichedAppBLB
	ListenerList             []enrichedAppListener
	SecurityGroups           []appblb.BlbSecurityGroupModel
	EnterpriseSecurityGroups []appblb.BlbEnterpriseSecurityGroupModel
	AppServerGroupList       []enrichedAppServerGroup
}

func GetAppBLBResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.APPBLB,
		ResourceTypeName:  "APP BLB",
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.baidu.com/doc/BLB/s/Lkcznyjer`,
		Regions: []string{
			"blb.bj.baidubce.com",
			"blb.gz.baidubce.com",
			"blb.su.baidubce.com",
			"blb.hkg.baidubce.com",
			"blb.fwh.baidubce.com",
			"blb.bd.baidubce.com",
			"blb.fsh.baidubce.com",
			"blb.sin.baidubce.com",
		},
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*collector.Services).APPBLBClient

			marker := ""
			for {
				response, err := describeAppLoadBalancersEnriched(ctx, client, marker)
				if err != nil {
					log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
					return err
				}
				for _, i := range response.BlbList {
					d := AppBLBDetail{
						AppBLB:                   i,
						ListenerList:             describeAppAllListeners(ctx, client, i.BlbId),
						SecurityGroups:           describeAppBLBSecurityGroups(ctx, client, i.BlbId),
						EnterpriseSecurityGroups: describeAppBLBEnterpriseSecurityGroups(ctx, client, i.BlbId),
						AppServerGroupList:       describeAppServerGroup(ctx, client, i.BlbId),
					}
					res <- d
				}
				if response.NextMarker == "" {
					break
				}
				marker = response.NextMarker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.AppBLB.blbId",
			ResourceName: "$.AppBLB.name",
			Address:      "$.AppBLB.publicIp",
		},
		Dimension: schema.Regional,
	}
}

// describeAppLoadBalancersEnriched mirrors client.DescribeLoadBalancers but
// decodes into enrichedDescribeAppLoadBalancersResult so the 8 extra fields
// returned by /v1/appblb are preserved.
func describeAppLoadBalancersEnriched(ctx context.Context, client *appblb.Client, marker string) (*enrichedDescribeAppLoadBalancersResult, error) {
	result := &enrichedDescribeAppLoadBalancersResult{}
	rb := bce.NewRequestBuilder(client).
		WithMethod("GET").
		WithURL("/v1/appblb").
		WithQueryParam("maxKeys", strconv.Itoa(1000)).
		WithResult(result)
	if marker != "" {
		rb = rb.WithQueryParam("marker", marker)
	}
	if err := rb.Do(); err != nil {
		return nil, err
	}
	return result, nil
}

func describeAppAllListeners(ctx context.Context, client *appblb.Client, blbId string) (listenerList []enrichedAppListener) {
	marker := ""
	for {
		result := &enrichedDescribeAppAllListenersResult{}
		rb := bce.NewRequestBuilder(client).
			WithMethod("GET").
			WithURL("/v1/appblb/" + blbId + "/listener").
			WithQueryParam("maxKeys", strconv.Itoa(50)).
			WithResult(result)
		if marker != "" {
			rb = rb.WithQueryParam("marker", marker)
		}
		if err := rb.Do(); err != nil {
			log.CtxLogger(ctx).Warn("DescribeAppAllListeners error", zap.Error(err))
			return
		}
		listenerList = append(listenerList, result.ListenerList...)
		if result.NextMarker == "" {
			break
		}
		marker = result.NextMarker
	}
	return listenerList
}

func describeAppBLBSecurityGroups(ctx context.Context, client *appblb.Client, blbId string) []appblb.BlbSecurityGroupModel {
	resp, err := client.DescribeSecurityGroups(blbId)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeAppBLBSecurityGroups error", zap.Error(err))
		return nil
	}

	return resp.BlbSecurityGroups
}

func describeAppBLBEnterpriseSecurityGroups(ctx context.Context, client *appblb.Client, blbId string) []appblb.BlbEnterpriseSecurityGroupModel {
	resp, err := client.DescribeEnterpriseSecurityGroups(blbId)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeAppBLBEnterpriseSecurityGroups error", zap.Error(err))
		return nil
	}

	return resp.BlbEnterpriseSecurityGroups
}

func describeAppServerGroup(ctx context.Context, client *appblb.Client, blbId string) (appServerGroupList []enrichedAppServerGroup) {
	marker := ""
	for {
		result := &enrichedDescribeAppServerGroupResult{}
		rb := bce.NewRequestBuilder(client).
			WithMethod("GET").
			WithURL("/v1/appblb/" + blbId + "/appservergroup").
			WithQueryParam("maxKeys", strconv.Itoa(50)).
			WithResult(result)
		if marker != "" {
			rb = rb.WithQueryParam("marker", marker)
		}
		if err := rb.Do(); err != nil {
			log.CtxLogger(ctx).Warn("describeAppServerGroup error", zap.Error(err))
			return
		}
		appServerGroupList = append(appServerGroupList, result.AppServerGroupList...)
		if result.NextMarker == "" {
			break
		}
		marker = result.NextMarker
	}
	return appServerGroupList
}
