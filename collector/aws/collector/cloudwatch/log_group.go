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

package cloudwatch

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetLogGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudWatchLogGroup,
		ResourceTypeName:   "CloudWatch Log Group",
		ResourceGroupType:  constant.LOG,
		ResourceDetailFunc: GetLogGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.LogGroup.Arn",
			ResourceName: "$.LogGroup.LogGroupName",
		},
		Dimension: schema.Regional,
	}
}

type LogGroupDetail struct {
	LogGroup         types.LogGroup
	MetricFilters    []types.MetricFilter
	ResourcePolicies []types.ResourcePolicy
	Tags             map[string]string
}

func GetLogGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CloudWatchLogs

	logGroups, err := describeLogGroups(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe log groups", zap.Error(err))
		return err
	}

	for _, lg := range logGroups {
		metricFilters, err := describeMetricFilters(ctx, client, lg.LogGroupName)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe metric filters", zap.String("loggroup", *lg.LogGroupName), zap.Error(err))
			return err
		}

		policies, err := describeResourcePolicies(ctx, client)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe resource policies", zap.Error(err))
			return err
		}

		tags, err := listTagsForLogGroup(ctx, client, lg.Arn)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list tags for log group", zap.String("loggroup", *lg.Arn), zap.Error(err))
			return err
		}

		res <- &LogGroupDetail{
			LogGroup:         lg,
			MetricFilters:    metricFilters,
			ResourcePolicies: policies,
			Tags:             tags,
		}
	}

	return nil
}

func describeLogGroups(ctx context.Context, client *cloudwatchlogs.Client) ([]types.LogGroup, error) {
	var logGroups []types.LogGroup
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, &cloudwatchlogs.DescribeLogGroupsInput{})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		logGroups = append(logGroups, output.LogGroups...)
	}
	return logGroups, nil
}

func describeMetricFilters(ctx context.Context, client *cloudwatchlogs.Client, logGroupName *string) ([]types.MetricFilter, error) {
	var metricFilters []types.MetricFilter
	paginator := cloudwatchlogs.NewDescribeMetricFiltersPaginator(client, &cloudwatchlogs.DescribeMetricFiltersInput{LogGroupName: logGroupName})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe metric filters", zap.String("loggroup", *logGroupName), zap.Error(err))
			return nil, err
		}
		metricFilters = append(metricFilters, output.MetricFilters...)
	}
	return metricFilters, nil
}

func describeResourcePolicies(ctx context.Context, client *cloudwatchlogs.Client) ([]types.ResourcePolicy, error) {
	var policies []types.ResourcePolicy
	out, err := client.DescribeResourcePolicies(ctx, &cloudwatchlogs.DescribeResourcePoliciesInput{})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to describe resource policies", zap.Error(err))
		return nil, err
	}
	policies = append(policies, out.ResourcePolicies...)
	if out.NextToken != nil {
		out, err = client.DescribeResourcePolicies(ctx, &cloudwatchlogs.DescribeResourcePoliciesInput{NextToken: out.NextToken})
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe resource policies", zap.Error(err))
			return nil, err
		}
		policies = append(policies, out.ResourcePolicies...)

		return policies, nil
	}

	return policies, nil
}

func listTagsForLogGroup(ctx context.Context, client *cloudwatchlogs.Client, logGroupArn *string) (map[string]string, error) {
	output, err := client.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{ResourceArn: logGroupArn})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for log group", zap.String("loggroup", *logGroupArn), zap.Error(err))
		return nil, err
	}
	return output.Tags, nil
}
