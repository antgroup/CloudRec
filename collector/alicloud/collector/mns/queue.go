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

package mns

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/mns-open"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetMessageServiceQueueResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MessageServiceQueue,
		ResourceTypeName:   collector.MessageServiceQueue,
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               `https://api.aliyun.com/product/Mns-open`,
		ResourceDetailFunc: GetQueueDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Queue.QueueName",
			ResourceName: "$.Queue.QueueName",
		},
		Dimension: schema.Regional,
	}
}

type QueueDetail struct {
	Queue           mns_open.PageDataItem
	QueueAttributes mns_open.Data
}

type QueueSecurityConfig struct {
	VisibilityTimeout      int64  `json:"visibility_timeout"`
	MaximumMessageSize     int64  `json:"maximum_message_size"`
	MessageRetentionPeriod int64  `json:"message_retention_period"`
	PollingWaitSeconds     int64  `json:"polling_wait_seconds"`
	DelaySeconds           int64  `json:"delay_seconds"`
	LoggingEnabled         bool   `json:"logging_enabled"`
	NotifyStrategy         string `json:"notify_strategy"`
	NotifyContentFormat    string `json:"notify_content_format"`
	CreateTime             int64  `json:"create_time"`
	LastModifyTime         int64  `json:"last_modify_time"`
}

func GetQueueDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).MnsOpen

	request := mns_open.CreateListQueueRequest()
	request.Scheme = "https"
	request.RegionId = *service.(*collector.Services).Config.RegionId

	// Set default pagination parameters
	request.PageNum = "1"
	request.PageSize = "100"

	for {
		response, err := cli.ListQueue(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListQueue error", zap.Error(err))
			return err
		}

		if len(response.Data.PageData) == 0 {
			break
		}

		for _, queue := range response.Data.PageData {
			// Get detailed queue attributes
			queueAttributes := getQueueAttributes(ctx, cli, queue.QueueName, request.RegionId)

			// Create queue detail
			d := QueueDetail{
				Queue:           queue,
				QueueAttributes: queueAttributes,
			}

			res <- d
		}

		// Check if there are more pages
		currentPage := response.Data.PageNum
		pageSize := response.Data.PageSize
		totalCount := response.Data.Total

		// Calculate if there are more pages
		if currentPage*pageSize >= totalCount {
			break
		}

		// Move to next page
		nextPage := currentPage + 1
		request.PageNum = requests.NewInteger(int(nextPage))
	}

	return nil
}

func getQueueAttributes(ctx context.Context, cli *mns_open.Client, queueName string, regionId string) mns_open.Data {
	request := mns_open.CreateGetQueueAttributesRequest()
	request.Scheme = "https"
	request.RegionId = regionId
	request.QueueName = queueName

	response, err := cli.GetQueueAttributes(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetQueueAttributes error", zap.Error(err))
		return mns_open.Data{}
	}

	return response.Data
}
