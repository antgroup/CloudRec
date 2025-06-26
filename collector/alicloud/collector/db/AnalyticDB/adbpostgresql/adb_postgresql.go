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

package adbpostgresql

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	gpdb20160503 "github.com/alibabacloud-go/gpdb-20160503/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetAnalyticDBPostgreSQLResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.AnalyticDBPostgreSQL,
		ResourceTypeName:   collector.AnalyticDBPostgreSQL,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/gpdb`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.DBInstanceId",
			ResourceName: "$.DBInstance.DBInstanceDescription",
		},
		Regions: []string{
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).AdbPostgreSQL

	request := &gpdb20160503.DescribeDBInstancesRequest{
		RegionId: cli.RegionId,
	}
	request.PageSize = tea.Int32(30)
	request.PageNumber = tea.Int32(1)

	count := 0
	for {
		resp, err := cli.DescribeDBInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeDBInstances error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.Items.DBInstance {
			res <- &Detail{
				DBInstance:          i,
				DBInstanceAttribute: describeDBInstanceAttribute(ctx, cli, i.DBInstanceId),
				DBInstanceIPArray:   describeDBInstanceIPArrayList(ctx, cli, i.DBInstanceId),
				DBInstanceNetInfos:  describeDBInstanceNetInfo(ctx, cli, i.DBInstanceId),
			}
		}

		count += len(resp.Body.Items.DBInstance)
		if count >= int(*resp.Body.TotalRecordCount) {
			break
		}

		*request.PageNumber = *resp.Body.PageNumber + 1
	}
	return nil
}

func describeDBInstanceNetInfo(ctx context.Context, cli *gpdb20160503.Client, dBInstanceId *string) *gpdb20160503.DescribeDBInstanceNetInfoResponseBodyDBInstanceNetInfos {
	request := &gpdb20160503.DescribeDBInstanceNetInfoRequest{
		DBInstanceId: dBInstanceId,
	}
	resp, err := cli.DescribeDBInstanceNetInfo(request)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceNetInfo error", zap.Error(err))
		return nil
	}
	return resp.Body.DBInstanceNetInfos
}

type Detail struct {
	DBInstance          *gpdb20160503.DescribeDBInstancesResponseBodyItemsDBInstance
	DBInstanceAttribute *gpdb20160503.DescribeDBInstanceAttributeResponseBodyItemsDBInstanceAttribute
	DBInstanceIPArray   []*gpdb20160503.DescribeDBInstanceIPArrayListResponseBodyItemsDBInstanceIPArray
	DBInstanceNetInfos  *gpdb20160503.DescribeDBInstanceNetInfoResponseBodyDBInstanceNetInfos
}

// Querying AnalyticDB PostgreSQL instance details
func describeDBInstanceAttribute(ctx context.Context, cli *gpdb20160503.Client, DBInstanceId *string) (Detail *gpdb20160503.DescribeDBInstanceAttributeResponseBodyItemsDBInstanceAttribute) {
	request := &gpdb20160503.DescribeDBInstanceAttributeRequest{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeDBInstanceAttribute(request)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceAttribute error", zap.Error(err))
		return
	}

	return resp.Body.Items.DBInstanceAttribute[0]
}

// Query the IP whitelist that is allowed to access the AnalyticDB PostgreSQL instance
func describeDBInstanceIPArrayList(ctx context.Context, cli *gpdb20160503.Client, DBInstanceId *string) (DBInstanceIPArray []*gpdb20160503.DescribeDBInstanceIPArrayListResponseBodyItemsDBInstanceIPArray) {
	req := &gpdb20160503.DescribeDBInstanceIPArrayListRequest{}
	req.DBInstanceId = DBInstanceId

	resp, err := cli.DescribeDBInstanceIPArrayList(req)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceIPArrayList error", zap.Error(err))
		return
	}
	return resp.Body.Items.DBInstanceIPArray
}
