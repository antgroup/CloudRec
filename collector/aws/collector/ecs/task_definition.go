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
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetTaskDefinitionResource returns a TaskDefinition Resource
func GetTaskDefinitionResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECSTaskDefinition,
		ResourceTypeName:   "ECS Task Definition",
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html`,
		ResourceDetailFunc: GetTaskDefinitionDetail,
		RowField: schema.RowField{
			ResourceId:   "$.TaskDefinition.TaskDefinitionArn",
			ResourceName: "$.TaskDefinition.Family",
		},
		Dimension: schema.Regional,
	}
}

// TaskDefinitionDetail aggregates all information for a single ECS task definition.
type TaskDefinitionDetail struct {
	TaskDefinition types.TaskDefinition
}

// GetTaskDefinitionDetail fetches the details for all ECS task definitions in a region.
func GetTaskDefinitionDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECS

	taskDefinitionArns, err := listTaskDefinitions(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list ecs task definitions", zap.Error(err))
		return err
	}

	for _, taskDefinitionArn := range taskDefinitionArns {
		taskDefinitionDetail := describeTaskDefinition(ctx, client, taskDefinitionArn)

		res <- taskDefinitionDetail
	}

	return nil
}

// listTaskDefinitions retrieves all ECS task definition ARNs in a region.
func listTaskDefinitions(ctx context.Context, c *ecs.Client) ([]string, error) {
	var taskDefinitionArns []string
	paginator := ecs.NewListTaskDefinitionsPaginator(c, &ecs.ListTaskDefinitionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		taskDefinitionArns = append(taskDefinitionArns, page.TaskDefinitionArns...)
	}
	return taskDefinitionArns, nil
}

// describeTaskDefinition retrieves the details for a single task definition.
func describeTaskDefinition(ctx context.Context, c *ecs.Client, taskDefinitionArn string) *TaskDefinitionDetail {
	output, err := c.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &taskDefinitionArn, Include: []types.TaskDefinitionField{types.TaskDefinitionFieldTags}})
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe ecs task definition", zap.Error(err))
		return nil
	}
	return &TaskDefinitionDetail{TaskDefinition: *output.TaskDefinition}
}
