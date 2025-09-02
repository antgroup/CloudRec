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

package ec2

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetFlowLogResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.FlowLog,
		ResourceTypeName:   "Flow Log",
		ResourceGroupType:  constant.NET,
		Desc:               "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeFlowLogs.html",
		ResourceDetailFunc: GetFlowLogDetail,
		RowField: schema.RowField{
			ResourceId:   "$.FlowLog.FlowLogId",
			ResourceName: "$.FlowLog.FlowLogId",
		},
		Dimension: schema.Regional,
	}
}

type FlowLogDetail struct {
	FlowLog types.FlowLog
}

func GetFlowLogDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EC2

	flowLogs, err := describeFlowLogs(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe flow logs", zap.Error(err))
		return err
	}

	for _, fl := range flowLogs {
		res <- FlowLogDetail{FlowLog: fl}
	}

	return nil
}

func describeFlowLogs(ctx context.Context, c *ec2.Client) ([]types.FlowLog, error) {
	var flowLogs []types.FlowLog

	paginator := ec2.NewDescribeFlowLogsPaginator(c, &ec2.DescribeFlowLogsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		flowLogs = append(flowLogs, page.FlowLogs...)
	}
	return flowLogs, nil
}
