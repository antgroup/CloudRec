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
	"fmt"

	"github.com/cloudrec/hws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	ecsModel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3"
	vpcModel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
	"go.uber.org/zap"
)

func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECS,
		ResourceTypeName:   "ECS Instance",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/ECS/doc?api=NovaListVersions",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ServerDetail.id",
			ResourceName: "$.ServerDetail.name",
		},
		Dimension: schema.Regional,
	}
}

type InstanceDetail struct {
	ServerDetail  ecsModel.ServerDetail
	SecurityGroup []*vpcModel.SecurityGroupInfo
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECS
	vpcClient := service.(*collector.Services).VPC

	limit := int32(50)
	offset := int32(1)
	request := &ecsModel.ListServersDetailsRequest{
		Limit:  &limit,
		Offset: &offset,
	}
	for {
		response, err := client.ListServersDetails(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListServersDetails error", zap.Error(err))
			return err
		}

		for _, ecs := range *response.Servers {
			ecs.OSEXTSRVATTRuserData = nil
			res <- &InstanceDetail{
				ServerDetail:  ecs,
				SecurityGroup: getSecurityGroup(ecs.SecurityGroups, vpcClient),
			}
		}

		if len(*response.Servers) < int(limit) {
			break
		}

		*request.Offset = *request.Offset + 1
	}
	return nil
}

func getSecurityGroup(securityGroups []ecsModel.ServerSecurityGroup, client *vpc.VpcClient) []*vpcModel.SecurityGroupInfo {
	var result []*vpcModel.SecurityGroupInfo
	for _, securityGroup := range securityGroups {
		request := &vpcModel.ShowSecurityGroupRequest{}
		request.SecurityGroupId = securityGroup.Id
		response, err := client.ShowSecurityGroup(request)
		result = append(result, response.SecurityGroup)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("get SecurityGroup error: %s", err.Error()))
			return nil
		}
	}
	return result
}
