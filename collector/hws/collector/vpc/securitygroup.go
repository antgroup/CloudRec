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

package vpc

import (
	"context"

	"github.com/cloudrec/hws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3"
	vpcModel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
	"go.uber.org/zap"
)

func GetSecurityGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SecurityGroup,
		ResourceTypeName:   "Security Group",
		ResourceGroupType:  constant.NET,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/VPC/sdk?version=v3&api=ListSecurityGroups",
		ResourceDetailFunc: GetSecurityGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.SecurityGroup.id",
			ResourceName: "$.SecurityGroup.name",
		},
		Dimension: schema.Regional,
	}
}

type SecurityGroupDetail struct {
	Region      string
	SecurityGroup vpcModel.SecurityGroup
	SecurityGroupDetail *vpcModel.SecurityGroupInfo
}

func GetSecurityGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.VPC

	request := &vpcModel.ListSecurityGroupsRequest{}
	for {
		response, err := cli.ListSecurityGroups(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListSecurityGroups error", zap.Error(err))
			return err
		}

		for _, securityGroup := range *response.SecurityGroups {
			res <- &SecurityGroupDetail{
				Region:      services.Region,
				SecurityGroup: securityGroup,
				SecurityGroupDetail: getSecurityGroupRules(ctx, securityGroup, cli),
			}
		}

		if response.SecurityGroups == nil || len(*response.SecurityGroups) == 0 {
			break
		}

		lastSecurityGroup := (*response.SecurityGroups)[len(*response.SecurityGroups)-1]

		request.Marker = &lastSecurityGroup.Id
	}
	return nil
}

func getSecurityGroupRules(ctx context.Context, securityGroup vpcModel.SecurityGroup, client *vpc.VpcClient) *vpcModel.SecurityGroupInfo {
	request := &vpcModel.ShowSecurityGroupRequest{}
	request.SecurityGroupId = securityGroup.Id
	response, err := client.ShowSecurityGroup(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("get SecurityGroup error", zap.Error(err))
		return nil
	}
	return response.SecurityGroup
}