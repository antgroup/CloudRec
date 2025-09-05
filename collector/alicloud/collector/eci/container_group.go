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

package eci

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eci"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetECIContainerGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECIContainerGroup,
		ResourceTypeName:   "ECI ContainerGroup",
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://api.aliyun.com/product/Eci`,
		ResourceDetailFunc: GetECIContainerGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ContainerGroup.ContainerGroupId",
			ResourceName: "$.ContainerGroup.ContainerGroupName",
		},
		Dimension: schema.Regional,
	}
}

type ECIContainerGroupDetail struct {
	ContainerGroup eci.DescribeContainerGroupsContainerGroup0
}

// GetECIContainerGroupDetail 实现弹性容器实例组的安全信息收集
func GetECIContainerGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ECI

	// 1. DescribeContainerGroups - 获取容器组列表，返回安全组ID、VPC配置等
	request := eci.CreateDescribeContainerGroupsRequest()
	request.Scheme = "https"

	for {
		response, err := cli.DescribeContainerGroups(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeContainerGroups error", zap.Error(err))
			return err
		}

		// 处理容器组
		for _, cg := range response.ContainerGroups {
			detail := ECIContainerGroupDetail{
				ContainerGroup: cg,
			}

			res <- detail
		}
		if response.NextToken == "" {
			break
		}
		request.NextToken = response.NextToken
	}

	return nil
}
