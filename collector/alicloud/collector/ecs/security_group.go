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

package ecs

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	aliecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

type SecurityGroup struct {
	SecurityGroup aliecs.SecurityGroup
	Permissions   []aliecs.Permission
}

func GetSecurityGroupData() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SecurityGroup,
		ResourceTypeName:   "Security Group",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Ecs`,
		ResourceDetailFunc: DescribeSecurityGroups,
		RowField: schema.RowField{
			ResourceId:   "$.SecurityGroup.SecurityGroupId",
			ResourceName: "$.SecurityGroup.SecurityGroupName",
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
			"us-southeast-1",
			"na-south-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func DescribeSecurityGroups(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ECS
	req := aliecs.CreateDescribeSecurityGroupsRequest()
	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		resp, err := cli.DescribeSecurityGroups(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeSecurityGroups error", zap.Error(err))
			return err
		}
		count += len(resp.SecurityGroups.SecurityGroup)
		for i := 0; i < len(resp.SecurityGroups.SecurityGroup); i++ {
			permissions, err := describeSecurityGroupAttribute(ctx, cli, resp.SecurityGroups.SecurityGroup[i].SecurityGroupId)
			if err != nil {
				continue
			}

			sg := SecurityGroup{
				SecurityGroup: resp.SecurityGroups.SecurityGroup[i],
				Permissions:   permissions,
			}

			res <- sg
		}
		if count >= resp.TotalCount || len(resp.SecurityGroups.SecurityGroup) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return nil
}

func describeSecurityGroupAttribute(ctx context.Context, cli *ecs.Client, sgId string) (permissions []aliecs.Permission, err error) {
	req := aliecs.CreateDescribeSecurityGroupAttributeRequest()
	req.SecurityGroupId = sgId

	resp, err := cli.DescribeSecurityGroupAttribute(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeSecurityGroupAttribute error", zap.Error(err))
		return nil, err
	}

	permissions = append(permissions, resp.Permissions.Permission...)
	return permissions, nil
}
