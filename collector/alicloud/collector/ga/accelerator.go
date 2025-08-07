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

package ga

import (
	"context"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ga"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetAcceleratorResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.GAAccelerator,
		ResourceTypeName:   "GA Accelerator",
		ResourceGroupType:  constant.NET,
		Desc:               "https://api.aliyun.com/product/Ga",
		ResourceDetailFunc: GetAcceleratorDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Accelerator.AcceleratorId",
			ResourceName: "$.Accelerator.Name",
		},
		Dimension: schema.Global,
	}
}

type AcceleratorDetail struct {
	Accelerator    ga.AcceleratorsItem
	Listeners      []Listener
	EndpointGroups []ga.EndpointGroupsItem
}

type Listener struct {
	Listener *ga.DescribeListenerResponse
	Acls     []*ga.GetAclResponse
}

func GetAcceleratorDetail(ctx context.Context, service schema.ServiceInterface, res chan<- interface{}) error {
	cli := service.(*collector.Services).GA

	request := ga.CreateListAcceleratorsRequest()
	request.Scheme = "https"
	request.PageSize = requests.NewInteger(50)
	pageNumber := 1

	for {
		request.PageNumber = requests.NewInteger(pageNumber)
		response, err := cli.ListAccelerators(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListAccelerators error", zap.Error(err))
			return err
		}

		if response.Accelerators == nil || len(response.Accelerators) == 0 {
			break
		}

		for _, accelerator := range response.Accelerators {
			detail := AcceleratorDetail{
				Accelerator:    accelerator,
				Listeners:      getListeners(ctx, cli, accelerator.AcceleratorId),
				EndpointGroups: getEndpointGroups(ctx, cli, accelerator.AcceleratorId),
			}
			res <- detail
		}

		if len(response.Accelerators) < 50 {
			break
		}
		pageNumber++
	}
	return nil
}

func getListeners(ctx context.Context, cli *ga.Client, id string) []Listener {
	listeners := listListeners(ctx, cli, id)

	var listenerList []Listener
	for _, l := range listeners {
		listener := describeListener(ctx, cli, l.ListenerId)
		Acls := getACLs(ctx, cli, listener.RelatedAcls)
		listenerList = append(listenerList, Listener{
			Listener: listener,
			Acls:     Acls,
		})
	}
	return listenerList
}

func getACLs(ctx context.Context, cli *ga.Client, acls []ga.RelatedAcls) []*ga.GetAclResponse {
	if len(acls) < 0 {
		return nil
	}

	var aclsResponse []*ga.GetAclResponse
	for _, a := range acls {
		acl := getAcl(ctx, cli, a.AclId)
		aclsResponse = append(aclsResponse, acl)
	}
	return aclsResponse
}

func getAcl(ctx context.Context, cli *ga.Client, id string) *ga.GetAclResponse {
	request := ga.CreateGetAclRequest()
	request.Scheme = "https"
	request.AclId = id

	response, err := cli.GetAcl(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAcl error", zap.Error(err))
		return nil
	}
	return response
}

func describeListener(ctx context.Context, cli *ga.Client, id string) *ga.DescribeListenerResponse {
	request := ga.CreateDescribeListenerRequest()
	request.Scheme = "https"
	request.ListenerId = id

	describeListenerResponse, err := cli.DescribeListener(request)
	if err != nil {
		return nil
	}
	return describeListenerResponse
}

func listListeners(ctx context.Context, cli *ga.Client, acceleratorId string) []ga.ListenersItem {
	request := ga.CreateListListenersRequest()
	request.Scheme = "https"
	request.AcceleratorId = acceleratorId
	request.PageSize = requests.NewInteger(100)

	var allListeners []ga.ListenersItem
	pageNumber := 1
	count := 0
	for {
		request.PageNumber = requests.NewInteger(pageNumber)
		response, err := cli.ListListeners(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListListeners error", zap.Error(err))
			return allListeners
		}

		allListeners = append(allListeners, response.Listeners...)

		count += len(response.Listeners)
		if count >= response.TotalCount || len(response.Listeners) == 0 {
			break
		}
		pageNumber++
	}

	return allListeners
}

func getEndpointGroups(ctx context.Context, cli *ga.Client, acceleratorId string) []ga.EndpointGroupsItem {
	request := ga.CreateListEndpointGroupsRequest()
	request.Scheme = "https"
	request.AcceleratorId = acceleratorId
	request.PageSize = requests.NewInteger(100)

	var allEndpointGroups []ga.EndpointGroupsItem
	pageNumber := 1

	for {
		request.PageNumber = requests.NewInteger(pageNumber)
		response, err := cli.ListEndpointGroups(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListEndpointGroups error", zap.Error(err))
			return allEndpointGroups
		}

		allEndpointGroups = append(allEndpointGroups, response.EndpointGroups...)

		if len(response.EndpointGroups) < 100 {
			break
		}
		pageNumber++
	}

	return allEndpointGroups
}
