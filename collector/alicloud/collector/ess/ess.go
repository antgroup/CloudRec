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

package ess

import (
	"context"
	ess "github.com/alibabacloud-go/ess-20220222/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetESSResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ESS,
		ResourceTypeName:   "ESS",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://api.aliyun.com/product/Ess",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ScalingGroup.ScalingGroupId",
			ResourceName: "$.ScalingGroup.ScalingGroupName",
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
			"me-east-1",
			"me-central-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ESS
	describeScalingGroupsRequest := &ess.DescribeScalingGroupsRequest{}
	describeScalingGroupsRequest.RegionId = cli.RegionId
	describeScalingGroupsRequest.PageSize = tea.Int32(int32(50))
	describeScalingGroupsRequest.PageNumber = tea.Int32(int32(1))
	count := 0

	for {
		scalingGroups, err := cli.DescribeScalingGroupsWithOptions(describeScalingGroupsRequest, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeScalingGroupsWithOptions error", zap.Error(err))
			return err
		}

		// If the region has no scaling group, skip subsequent queries
		if len(scalingGroups.Body.ScalingGroups) == 0 {
			return nil
		}

		for _, scalingGroup := range scalingGroups.Body.ScalingGroups {
			res <- Detail{
				RegionId:          cli.RegionId,
				ScalingGroup:      scalingGroup,
				EcsConfigurations: describeEcsScalingConfiguration(ctx, cli, cli.RegionId),
				EciConfigurations: describeEciScalingConfigurations(ctx, cli, cli.RegionId),
				AlarmList:         describeAlarms(ctx, cli, cli.RegionId),
			}
			count++
		}

		if count >= int(*scalingGroups.Body.TotalCount) {
			break
		}
		describeScalingGroupsRequest.PageNumber = tea.Int32(*describeScalingGroupsRequest.PageNumber + 1)
	}
	return nil
}

type Detail struct {
	// region
	RegionId *string

	// Scaling group information
	ScalingGroup *ess.DescribeScalingGroupsResponseBodyScalingGroups

	// ECS type scaling configuration information
	EcsConfigurations []*ess.DescribeScalingConfigurationsResponseBodyScalingConfigurations

	// ECI type scaling configuration information
	EciConfigurations []*ess.DescribeEciScalingConfigurationsResponseBodyScalingConfigurations

	// Alarm settings
	AlarmList []*ess.DescribeAlarmsResponseBodyAlarmList
}

// Query ECS type scaling configuration information
func describeEcsScalingConfiguration(ctx context.Context, cli *ess.Client, regionId *string) []*ess.DescribeScalingConfigurationsResponseBodyScalingConfigurations {

	describeScalingConfigurationsRequest := &ess.DescribeScalingConfigurationsRequest{
		RegionId: regionId,
	}

	result, err := cli.DescribeScalingConfigurationsWithOptions(describeScalingConfigurationsRequest, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeScalingConfigurationsWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.ScalingConfigurations
}

func describeEciScalingConfigurations(ctx context.Context, cli *ess.Client, regionId *string) []*ess.DescribeEciScalingConfigurationsResponseBodyScalingConfigurations {
	describeEciScalingConfigurationsRequest := &ess.DescribeEciScalingConfigurationsRequest{
		RegionId: regionId,
	}

	result, err := cli.DescribeEciScalingConfigurationsWithOptions(describeEciScalingConfigurationsRequest, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeEciScalingConfigurationsWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.ScalingConfigurations
}

// Query alarm task information
func describeAlarms(ctx context.Context, cli *ess.Client, regionId *string) []*ess.DescribeAlarmsResponseBodyAlarmList {
	describeAlarmsRequest := &ess.DescribeAlarmsRequest{
		RegionId: regionId,
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeAlarmsWithOptions(describeAlarmsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAlarmsWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.AlarmList
}
