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

package dbs

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dbs"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetDBSBackupPlanResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DBSBackupPlan,
		ResourceTypeName:   collector.DBSBackupPlan,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/DBS`,
		ResourceDetailFunc: GetBackupPlanDetail,
		RowField: schema.RowField{
			ResourceId:   "$.BackupPlan.BackupPlanId",
			ResourceName: "$.BackupPlan.BackupPlanName",
		},
		Dimension: schema.Global,
	}
}

type BackupPlanDetail struct {
	BackupPlan        dbs.BackupPlanDetail
	BackupPlanBilling dbs.Item
}

func GetBackupPlanDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services)

	request := dbs.CreateDescribeBackupPlanListRequest()
	request.Scheme = "https"
	request.PageSize = "100"
	request.PageNum = "1"

	for {
		response, err := cli.DBS.DescribeBackupPlanList(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeBackupPlanList error", zap.Error(err))
			return err
		}

		if response.Items.BackupPlanDetail == nil || len(response.Items.BackupPlanDetail) == 0 {
			break
		}

		for _, plan := range response.Items.BackupPlanDetail {
			backupPlanDetail := plan
			billingDetail := getBackupPlanBilling(ctx, cli, plan.BackupPlanId)

			detail := BackupPlanDetail{
				BackupPlan:        backupPlanDetail,
				BackupPlanBilling: billingDetail,
			}

			res <- detail
		}

		// Check pagination
		totalCount := response.TotalElements
		pageNum := response.PageNum
		pageSize := response.PageSize

		if pageNum*pageSize >= totalCount {
			break
		}

		request.PageNum = requests.NewInteger(pageNum + 1)
	}
	return nil
}

func getBackupPlanBilling(ctx context.Context, cli *collector.Services, backupPlanId string) dbs.Item {
	request := dbs.CreateDescribeBackupPlanBillingRequest()
	request.Scheme = "https"
	request.BackupPlanId = backupPlanId

	response, err := cli.DBS.DescribeBackupPlanBilling(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeBackupPlanBilling error", zap.Error(err), zap.String("backupPlanId", backupPlanId))
		return dbs.Item{}
	}

	return response.Item
}
