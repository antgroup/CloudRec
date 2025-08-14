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

package autoscaling

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetGroupResource returns a Group Resource
func GetGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.AutoScalingGroup,
		ResourceTypeName:   "Auto Scaling Group",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               `https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DescribeAutoScalingGroups.html`,
		ResourceDetailFunc: GetGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Group.AutoScalingGroupARN",
			ResourceName: "$.Group.AutoScalingGroupName",
		},
		Dimension: schema.Regional,
	}
}

// GroupDetail aggregates all information for a single Auto Scaling group.
type GroupDetail struct {
	Group types.AutoScalingGroup
}

// GetGroupDetail fetches the details for all Auto Scaling groups in a region.
func GetGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).AutoScaling

	groups, err := listAutoScalingGroups(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list auto scaling groups", zap.Error(err))
		return err
	}

	for _, group := range groups {
		res <- GroupDetail{Group: group}
	}

	return nil
}

// listAutoScalingGroups retrieves all Auto Scaling groups in a region.
func listAutoScalingGroups(ctx context.Context, c *autoscaling.Client) ([]types.AutoScalingGroup, error) {
	var groups []types.AutoScalingGroup
	paginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(c, &autoscaling.DescribeAutoScalingGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		groups = append(groups, page.AutoScalingGroups...)
	}
	return groups, nil
}
