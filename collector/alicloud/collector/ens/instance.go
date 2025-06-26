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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ens"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ENSInstance,
		ResourceTypeName:   "ENS Instance",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               `https://api.aliyun.com/product/Ens`,
		ResourceDetailFunc: ListInstanceResource,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
			Address:      "$.Instance.PublicIpAddress",
		},
		Regions:   []string{"cn-hangzhou"},
		Dimension: schema.Global,
	}
}

type InstanceDetail struct {
	Instance       ens.Instance
	SecurityGroups []SecurityGroupAttribute
}

type SecurityGroupAttribute struct {
	Description       string          `json:"Description" xml:"Description"`
	SecurityGroupId   string          `json:"SecurityGroupId" xml:"SecurityGroupId"`
	SecurityGroupName string          `json:"SecurityGroupName" xml:"SecurityGroupName"`
	Permissions       ens.Permissions `json:"Permissions" xml:"Permissions"`
}

func ListInstanceResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ENS
	describeInstancesRequest := ens.CreateDescribeInstancesRequest()
	describeInstancesResponse, err := cli.DescribeInstances(describeInstancesRequest)
	if err != nil {
		log.CtxLogger(ctx).Error("ListInstanceResource error", zap.Error(err))
		return err
	}
	for describeInstancesResponse.PageSize*describeInstancesResponse.PageNumber <= describeInstancesResponse.TotalCount {
		for _, instance := range describeInstancesResponse.Instances.Instance {
			instanceDetail := InstanceDetail{
				Instance:       instance,
				SecurityGroups: describeSecurityGroups(ctx, cli, instance.SecurityGroupIds.SecurityGroupId),
			}

			res <- instanceDetail
		}
		describeInstancesRequest.PageNumber = requests.NewInteger(describeInstancesResponse.PageNumber + 1)
		describeInstancesResponse, err = cli.DescribeInstances(describeInstancesRequest)
		if err != nil {
			return err
		}
	}
	return nil
}

func describeSecurityGroups(ctx context.Context, cli *ens.Client, ids []string) (securityGroups []SecurityGroupAttribute) {
	for _, id := range ids {
		securityGroups = append(securityGroups, describeSecurityGroupAttribute(ctx, cli, id))
	}
	return securityGroups
}

func describeSecurityGroupAttribute(ctx context.Context, cli *ens.Client, id string) SecurityGroupAttribute {
	request := ens.CreateDescribeSecurityGroupAttributeRequest()
	request.SecurityGroupId = id
	response, err := cli.DescribeSecurityGroupAttribute(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeSecurityGroupAttribute error", zap.Error(err))
		return SecurityGroupAttribute{}
	}

	return SecurityGroupAttribute{
		Description:       response.Description,
		SecurityGroupId:   response.SecurityGroupId,
		SecurityGroupName: response.SecurityGroupName,
		Permissions:       response.Permissions,
	}
}
