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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetAlarmResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudWatchAlarm,
		ResourceTypeName:   "CloudWatch Alarm",
		ResourceGroupType:  constant.LOG,
		ResourceDetailFunc: GetAlarmDetail,
		RowField: schema.RowField{
			ResourceId:   "$.MetricAlarm.AlarmArn",
			ResourceName: "$.MetricAlarm.AlarmName",
		},
		Dimension: schema.Regional,
	}
}

type AlarmDetail struct {
	MetricAlarm types.MetricAlarm
	Tags        []types.Tag
}

func GetAlarmDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CloudWatch

	alarms, err := describeAlarms(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe alarms", zap.Error(err))
		return err
	}

	for _, alarm := range alarms {
		tags, err := client.ListTagsForResource(ctx, &cloudwatch.ListTagsForResourceInput{
			ResourceARN: alarm.AlarmArn,
		})
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list tags for alarm", zap.String("alarm", *alarm.AlarmArn), zap.Error(err))
		}
		res <- &AlarmDetail{
			MetricAlarm: alarm,
			Tags:        tags.Tags,
		}

	}

	return nil
}

func describeAlarms(ctx context.Context, client *cloudwatch.Client) ([]types.MetricAlarm, error) {
	var alarms []types.MetricAlarm
	paginator := cloudwatch.NewDescribeAlarmsPaginator(client, &cloudwatch.DescribeAlarmsInput{})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		alarms = append(alarms, output.MetricAlarms...)
	}
	return alarms, nil
}
