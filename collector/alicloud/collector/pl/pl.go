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

package pl

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"go.uber.org/zap"

	privatelink "github.com/alibabacloud-go/privatelink-20200415/v5/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
)

func GetPrivateLinkResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.PrivateLink,
		ResourceTypeName:   "PrivateLink",
		ResourceGroupType:  constant.NET,
		Desc:               "https://api.aliyun.com/product/Privatelink",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.EndpointService.ServiceId",
			ResourceName: "$.EndpointService.ServiceName",
			Address:      "$.EndpointService.ServiceDomain",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
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
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Privatelink
	listVpcEndpointServicesRequest := &privatelink.ListVpcEndpointServicesRequest{}
	listVpcEndpointServicesRequest.RegionId = cli.RegionId
	listVpcEndpointServicesRequest.MaxResults = tea.Int32(1000)
	count := 0

	for {
		runtime := &util.RuntimeOptions{}

		endpointServices, err := cli.ListVpcEndpointServicesWithOptions(listVpcEndpointServicesRequest, runtime)
		if err != nil {
			log.CtxLogger(ctx).Error("GetPrivateLinkResource error", zap.Error(err))
			return err
		}

		// If no node is found, continue
		if len(endpointServices.Body.Services) == 0 {
			return nil
		}

		for _, s := range endpointServices.Body.Services {
			endpoint := describeVpcEndpoint(ctx, cli, cli.RegionId, s.ServiceName)

			var securityGroup []*privatelink.ListVpcEndpointSecurityGroupsResponseBodySecurityGroups
			if len(endpoint) == 0 {
				securityGroup = nil
			} else {
				securityGroup = describeVpcEndpointSecurityGroup(ctx, cli, cli.RegionId, endpoint[0].EndpointId)
			}

			res <- Detail{
				RegionId:        cli.RegionId,
				EndpointService: s,
				Endpoint:        endpoint,
				SecurityGroup:   securityGroup,
			}
			count++
		}
		if count >= int(*endpointServices.Body.TotalCount) {
			break
		}
		if endpointServices.Body.NextToken != nil {
			listVpcEndpointServicesRequest.NextToken = endpointServices.Body.NextToken
		} else {
			break
		}
	}
	return nil
}

type Detail struct {
	// region
	RegionId *string

	// Endpoint service information
	EndpointService *privatelink.ListVpcEndpointServicesResponseBodyServices

	// Endpoint information
	Endpoint []*privatelink.ListVpcEndpointsResponseBodyEndpoints

	// Security group information
	SecurityGroup []*privatelink.ListVpcEndpointSecurityGroupsResponseBodySecurityGroups
}

// query endpoint info
func describeVpcEndpoint(ctx context.Context, cli *privatelink.Client, regionId *string, serviceName *string) []*privatelink.ListVpcEndpointsResponseBodyEndpoints {
	listVpcEndpointsRequest := &privatelink.ListVpcEndpointsRequest{
		RegionId:    regionId,
		ServiceName: serviceName,
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListVpcEndpointsWithOptions(listVpcEndpointsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetPrivateLinkVpcEndpoint error", zap.Error(err))
		return nil
	}
	return result.Body.Endpoints
}

// Query security group information
func describeVpcEndpointSecurityGroup(ctx context.Context, cli *privatelink.Client, regionId *string, endpointId *string) []*privatelink.ListVpcEndpointSecurityGroupsResponseBodySecurityGroups {
	listVpcEndpointSecurityGroupsRequest := &privatelink.ListVpcEndpointSecurityGroupsRequest{
		RegionId:   regionId,
		EndpointId: endpointId,
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListVpcEndpointSecurityGroupsWithOptions(listVpcEndpointSecurityGroupsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetPrivateLinkSecurityGroup error", zap.Error(err))
		return nil
	}
	return result.Body.SecurityGroups
}
