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

func GetNetworkResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ENSNetwork,
		ResourceTypeName:   "ENS Network",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Ens`,
		ResourceDetailFunc: ListNetworkResource,
		RowField: schema.RowField{
			ResourceId:   "$.Network.NetworkId",
			ResourceName: "$.Network.NetworkName",
		},
		Regions:   []string{"cn-hangzhou"},
		Dimension: schema.Global,
	}
}

type NetworkDetail struct {
	Network    NetworkAttribute
	NetworkAcl ens.NetworkAcl
}
type NetworkAttribute struct {
	EnsRegionId    string                                   `json:"EnsRegionId" xml:"EnsRegionId"`
	NetworkId      string                                   `json:"NetworkId" xml:"NetworkId"`
	NetworkName    string                                   `json:"NetworkName" xml:"NetworkName"`
	CidrBlock      string                                   `json:"CidrBlock" xml:"CidrBlock"`
	Status         string                                   `json:"Status" xml:"Status"`
	Description    string                                   `json:"Description" xml:"Description"`
	CreatedTime    string                                   `json:"CreatedTime" xml:"CreatedTime"`
	RouterTableId  string                                   `json:"RouterTableId" xml:"RouterTableId"`
	NetworkAclId   string                                   `json:"NetworkAclId" xml:"NetworkAclId"`
	VSwitchIds     ens.VSwitchIdsInDescribeNetworkAttribute `json:"VSwitchIds" xml:"VSwitchIds"`
	CloudResources ens.CloudResources                       `json:"CloudResources" xml:"CloudResources"`
}

func ListNetworkResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ENS
	describeNetworksRequest := ens.CreateDescribeNetworksRequest()
	describeNetworksResponse, err := cli.DescribeNetworks(describeNetworksRequest)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeNetwork error", zap.Error(err))
		return err
	}

	for {
		for _, network := range describeNetworksResponse.Networks.Network {
			networkDetail := NetworkDetail{
				Network:    describeNetworkAttribute(ctx, cli, network.NetworkId),
				NetworkAcl: describeNetworkAcl(ctx, cli, network.NetworkId),
			}
			res <- networkDetail
		}

		if describeNetworksResponse.PageSize*describeNetworksResponse.PageNumber >= describeNetworksResponse.TotalCount {
			break
		}

		describeNetworksRequest.PageNumber = requests.NewInteger(describeNetworksResponse.PageNumber + 1)
		describeNetworksResponse, err = cli.DescribeNetworks(describeNetworksRequest)
		if err != nil {
			return err
		}
	}

	return nil
}

func describeNetworkAcl(ctx context.Context, cli *ens.Client, id string) ens.NetworkAcl {
	request := ens.CreateDescribeNetworkAclsRequest()
	request.ResourceId = id

	response, err := cli.DescribeNetworkAcls(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeNetworkAcls error", zap.Error(err))
		return ens.NetworkAcl{}
	}

	return response.NetworkAcls[0]
}

func describeNetworkAttribute(ctx context.Context, cli *ens.Client, id string) NetworkAttribute {
	request := ens.CreateDescribeNetworkAttributeRequest()
	request.NetworkId = id
	response, err := cli.DescribeNetworkAttribute(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeNetworkAttribute error", zap.Error(err))
		return NetworkAttribute{}
	}

	return NetworkAttribute{
		EnsRegionId:    response.EnsRegionId,
		NetworkId:      response.NetworkId,
		NetworkName:    response.NetworkName,
		CidrBlock:      response.CidrBlock,
		Status:         response.Status,
		Description:    response.Description,
		CreatedTime:    response.CreatedTime,
		RouterTableId:  response.RouterTableId,
		NetworkAclId:   response.NetworkAclId,
		VSwitchIds:     response.VSwitchIds,
		CloudResources: response.CloudResources,
	}
}
