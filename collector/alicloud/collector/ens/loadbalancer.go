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

package ens

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ens"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetLoadBalancerResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ENSLoadBalancer,
		ResourceTypeName:   "ENS LoadBalancer",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Ens`,
		ResourceDetailFunc: ListLoadBalancerResource,
		RowField: schema.RowField{
			ResourceId:   "$.LoadBalancer.LoadBalancerId",
			ResourceName: "$.LoadBalancer. LoadBalancerName",
			Address:      "$.LoadBalancer.Address",
		},
		Regions:   []string{"cn-hangzhou"},
		Dimension: schema.Global,
	}
}

type LoadBalancerDetail struct {
	LoadBalancer LoadBalancerAttribute
}

type LoadBalancerAttribute struct {
	LoadBalancerId            string         `json:"LoadBalancerId" xml:"LoadBalancerId"`
	LoadBalancerName          string         `json:"LoadBalancerName" xml:"LoadBalancerName"`
	LoadBalancerStatus        string         `json:"LoadBalancerStatus" xml:"LoadBalancerStatus"`
	EnsRegionId               string         `json:"EnsRegionId" xml:"EnsRegionId"`
	Address                   string         `json:"Address" xml:"Address"`
	NetworkId                 string         `json:"NetworkId" xml:"NetworkId"`
	VSwitchId                 string         `json:"VSwitchId" xml:"VSwitchId"`
	Bandwidth                 int            `json:"Bandwidth" xml:"Bandwidth"`
	LoadBalancerSpec          string         `json:"LoadBalancerSpec" xml:"LoadBalancerSpec"`
	CreateTime                string         `json:"CreateTime" xml:"CreateTime"`
	EndTime                   string         `json:"EndTime" xml:"EndTime"`
	AddressIPVersion          string         `json:"AddressIPVersion" xml:"AddressIPVersion"`
	PayType                   string         `json:"PayType" xml:"PayType"`
	ListenerPorts             []string       `json:"ListenerPorts" xml:"ListenerPorts"`
	BackendServers            []ens.Rs       `json:"BackendServers" xml:"BackendServers"`
	ListenerPortsAndProtocols []ens.Listener `json:"ListenerPortsAndProtocols" xml:"ListenerPortsAndProtocols"`
}

func ListLoadBalancerResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ENS
	describeLoadBalancerRequest := ens.CreateDescribeLoadBalancersRequest()
	describeLoadBalancerResponse, err := cli.DescribeLoadBalancers(describeLoadBalancerRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
		return err
	}
	for {
		for _, lb := range describeLoadBalancerResponse.LoadBalancers.LoadBalancer {
			loadBalancerDetail := LoadBalancerDetail{
				LoadBalancer: describeLoadBalancerAttribute(ctx, cli, lb.LoadBalancerId),
			}
			res <- loadBalancerDetail
		}

		if describeLoadBalancerResponse.PageSize*describeLoadBalancerResponse.PageNumber >= describeLoadBalancerResponse.TotalCount {
			break
		}

		describeLoadBalancerRequest.PageNumber = requests.NewInteger(describeLoadBalancerResponse.PageNumber + 1)
		describeLoadBalancerResponse, err = cli.DescribeLoadBalancers(describeLoadBalancerRequest)
		if err != nil {
			return err
		}
	}

	return nil
}

func describeLoadBalancerAttribute(ctx context.Context, cli *ens.Client, id string) LoadBalancerAttribute {
	request := ens.CreateDescribeLoadBalancerAttributeRequest()
	request.LoadBalancerId = id
	response, err := cli.DescribeLoadBalancerAttribute(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLoadBalancerAttribute error", zap.Error(err))
		return LoadBalancerAttribute{}
	}
	return LoadBalancerAttribute{
		LoadBalancerId:            response.LoadBalancerId,
		LoadBalancerName:          response.LoadBalancerName,
		LoadBalancerStatus:        response.LoadBalancerStatus,
		EnsRegionId:               response.EnsRegionId,
		Address:                   response.Address,
		NetworkId:                 response.NetworkId,
		VSwitchId:                 response.VSwitchId,
		Bandwidth:                 response.Bandwidth,
		LoadBalancerSpec:          response.LoadBalancerSpec,
		CreateTime:                response.CreateTime,
		EndTime:                   response.EndTime,
		AddressIPVersion:          response.AddressIPVersion,
		PayType:                   response.PayType,
		ListenerPorts:             response.ListenerPorts,
		BackendServers:            response.BackendServers,
		ListenerPortsAndProtocols: response.ListenerPortsAndProtocols,
	}
}
