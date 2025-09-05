// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ec2

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetVpcEndpointServiceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.VPCEndpointService,
		ResourceTypeName:   "VPC Endpoint Service",
		ResourceGroupType:  constant.NET,
		Desc:               "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcEndpointServices.html",
		ResourceDetailFunc: GetVpcEndpointServiceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Service.ServiceId",
			ResourceName: "$.Service.ServiceName",
		},
		Dimension: schema.Regional,
	}
}

type VpcEndpointServiceDetail struct {
	Service           types.ServiceDetail
	AllowedPrincipals []types.AllowedPrincipal
}

func GetVpcEndpointServiceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EC2

	services, err := describeVpcEndpointServices(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe vpc endpoint services", zap.Error(err))
		return err
	}

	for _, vpcEndpointService := range services {
		allowedPrincipals, err := describeVpcEndpointServicePermissions(ctx, client, vpcEndpointService.ServiceId)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe vpc endpoint service permissions", zap.String("serviceId", *vpcEndpointService.ServiceId), zap.Error(err))
		}

		res <- &VpcEndpointServiceDetail{
			Service:           vpcEndpointService,
			AllowedPrincipals: allowedPrincipals,
		}
	}

	return nil
}

func describeVpcEndpointServices(ctx context.Context, c *ec2.Client) ([]types.ServiceDetail, error) {
	var services []types.ServiceDetail
	out, err := c.DescribeVpcEndpointServices(ctx, &ec2.DescribeVpcEndpointServicesInput{})
	if err != nil {
		return nil, err
	}
	services = append(services, out.ServiceDetails...)

	for out.NextToken != nil {
		out, err = c.DescribeVpcEndpointServices(ctx, &ec2.DescribeVpcEndpointServicesInput{
			NextToken: out.NextToken,
		})
		if err != nil {
			return nil, err
		}
		services = append(services, out.ServiceDetails...)
	}

	return services, nil
}

func describeVpcEndpointServicePermissions(ctx context.Context, c *ec2.Client, id *string) ([]types.AllowedPrincipal, error) {
	var allowedPrincipals []types.AllowedPrincipal

	permissions, err := c.DescribeVpcEndpointServicePermissions(ctx, &ec2.DescribeVpcEndpointServicePermissionsInput{
		ServiceId: id,
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to describe vpc endpoint service permissions", zap.String("serviceId", *id), zap.Error(err))
	}

	for permissions.NextToken != nil {
		permissions, err = c.DescribeVpcEndpointServicePermissions(ctx, &ec2.DescribeVpcEndpointServicePermissionsInput{
			ServiceId: id,
			NextToken: permissions.NextToken,
		})
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe vpc endpoint service permissions", zap.String("serviceId", *id), zap.Error(err))
		}

		allowedPrincipals = append(allowedPrincipals, permissions.AllowedPrincipals...)
	}

	return permissions.AllowedPrincipals, nil
}
