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

package dts

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dts"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetDTSInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DTSInstance,
		ResourceTypeName:   "DTS Instance",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/Dts`,
		ResourceDetailFunc: GetDTSInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.MigrationJob.MigrationJobID",
			ResourceName: "$.MigrationJob.MigrationJobName",
		},
		Dimension: schema.Global,
	}
}

type DTSInstanceDetail struct {
	MigrationJob       dts.MigrationJob
	MigrationJobDetail dts.DescribeMigrationJobDetailResponse
}

// GetDTSInstanceDetail 实现数据传输服务实例的安全信息收集
func GetDTSInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).DTS

	// 1. DescirbeMigrationJobs - 获取DTS迁移任务列表
	request := dts.CreateDescirbeMigrationJobsRequest()
	request.Scheme = "https"
	var count int64 = 0
	for {
		response, err := cli.DescirbeMigrationJobs(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescirbeMigrationJobs error", zap.Error(err))
			return err
		}

		// 遍历所有DTS迁移任务
		for _, job := range response.MigrationJobs.MigrationJob {
			// 2. DescribeMigrationJobDetail - 获取DTS迁移任务详细信息
			jobDetail := describeMigrationJobDetail(ctx, cli, job.MigrationJobID)

			detail := DTSInstanceDetail{
				MigrationJob:       job,
				MigrationJobDetail: jobDetail,
			}

			res <- detail
		}

		count += int64(response.PageRecordCount)

		if count >= response.TotalRecordCount || response.PageRecordCount == 0 {
			break
		}
		request.PageNum = requests.NewInteger(response.PageNumber + 1)
	}

	return nil
}

// describeMigrationJobDetail 获取DTS迁移任务详细信息
func describeMigrationJobDetail(ctx context.Context, cli *dts.Client, migrationJobId string) dts.DescribeMigrationJobDetailResponse {
	request := dts.CreateDescribeMigrationJobDetailRequest()
	request.Scheme = "https"
	request.MigrationJobId = migrationJobId

	response, err := cli.DescribeMigrationJobDetail(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeMigrationJobDetail error", zap.Error(err))
		return dts.DescribeMigrationJobDetailResponse{}
	}

	return *response
}
