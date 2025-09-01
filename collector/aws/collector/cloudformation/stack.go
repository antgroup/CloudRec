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

package cloudformation

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetStackResource returns a Stack Resource
func GetStackResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudFormationStack,
		ResourceTypeName:   "CloudFormation Stack",
		ResourceGroupType:  constant.CONFIG,
		Desc:               `https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStacks.html`,
		ResourceDetailFunc: GetStackDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Stack.StackId",
			ResourceName: "$.Stack.StackName",
		},
		Dimension: schema.Regional,
	}
}

// StackDetail aggregates all information for a single CloudFormation stack.
type StackDetail struct {
	Stack types.Stack
}

// GetStackDetail fetches the details for all CloudFormation stacks in a region.
func GetStackDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CloudFormation

	stacks, err := describeStacks(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe cloudformation stacks", zap.Error(err))
		return err
	}

	for _, stack := range stacks {
		res <- StackDetail{Stack: stack}
	}

	return nil
}

// describeStacks retrieves all CloudFormation stacks in a region.
func describeStacks(ctx context.Context, c *cloudformation.Client) ([]types.Stack, error) {
	var stacks []types.Stack
	paginator := cloudformation.NewDescribeStacksPaginator(c, &cloudformation.DescribeStacksInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		stacks = append(stacks, page.Stacks...)
	}
	return stacks, nil
}
