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
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetSnapshotsResource 返回ECS快照资源定义
func GetSnapshotsResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECSSnapshot,
		ResourceTypeName:   "ECS Snapshot",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://www.alibabacloud.com/help/product/ecs.html",
		ResourceDetailFunc: GetSnapshotsDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Snapshot.SnapshotId",
			ResourceName: "$.Snapshot.SnapshotName",
		},
		Dimension: schema.Regional,
	}
}

type SnapshotDetail struct {
	Snapshot ecs.Snapshot
}

// GetSnapshotsDetail 获取ECS快照详细信息
func GetSnapshotsDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECS

	snapshots, err := listSnapshots(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list ecs snapshots", zap.Error(err))
		return err
	}

	for _, snapshot := range snapshots {
		res <- &SnapshotDetail{
			Snapshot: snapshot,
		}
	}

	return nil
}

// listSnapshots 获取ECS快照列表
func listSnapshots(ctx context.Context, c *ecs.Client) ([]ecs.Snapshot, error) {
	var snapshots []ecs.Snapshot

	// 使用分页模式
	req := ecs.CreateDescribeSnapshotsRequest()
	req.PageSize = requests.NewInteger(constant.DefaultPageSize)
	req.PageNumber = requests.NewInteger(constant.DefaultPage)

	count := 0
	for {
		resp, err := c.DescribeSnapshots(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeSnapshots error", zap.Error(err))
			return nil, err
		}

		snapshots = append(snapshots, resp.Snapshots.Snapshot...)
		count += len(resp.Snapshots.Snapshot)

		if count >= resp.TotalCount || len(resp.Snapshots.Snapshot) < constant.DefaultPageSize {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return snapshots, nil
}
