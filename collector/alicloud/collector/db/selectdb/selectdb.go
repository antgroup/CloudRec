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

package selectdb

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	selectdb20230522 "github.com/alibabacloud-go/selectdb-20230522/v3/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetSelectDBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SelectDB,
		ResourceTypeName:   collector.SelectDB,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/selectdb`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.DBInstanceId",
			ResourceName: "$.DBInstance.Description",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"ap-southeast-6",
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
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Selectdb

	request := &selectdb20230522.DescribeDBInstancesRequest{
		RegionId: cli.RegionId,
	}

	count := int64(0)
	for {
		runtime := &util.RuntimeOptions{}
		resp, err := cli.DescribeDBInstancesWithOptions(request, runtime)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeDBInstancesWithOptions error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.Items {
			res <- &Detail{
				DBInstance:     i,
				NetInfo:        describeDBInstanceNetInfo(ctx, cli, i.DBInstanceId),
				SecurityIPList: describeSecurityIPList(ctx, cli, i.DBInstanceId),
			}
		}

		count += int64(len(resp.Body.Items))
		if count >= tea.Int64Value(resp.Body.TotalRecordCount) {
			break
		}

		*request.PageNumber = *request.PageNumber + 1
	}
	return nil
}

type Detail struct {
	DBInstance     *selectdb20230522.DescribeDBInstancesResponseBodyItems
	NetInfo        *selectdb20230522.DescribeDBInstanceNetInfoResponseBody
	SecurityIPList *selectdb20230522.DescribeSecurityIPListResponseBody
}

// Query the network information of a specified cloud database SelectDB instance
func describeDBInstanceNetInfo(ctx context.Context, cli *selectdb20230522.Client, instanceId *string) (res *selectdb20230522.DescribeDBInstanceNetInfoResponseBody) {
	request := &selectdb20230522.DescribeDBInstanceNetInfoRequest{
		DBInstanceId: instanceId,
	}

	resp, err := cli.DescribeDBInstanceNetInfoWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceNetInfoWithOptions error", zap.Error(err))
		return
	}

	return resp.Body
}

// Query the whitelist IP address of a specified cloud database SelectDB instance
func describeSecurityIPList(ctx context.Context, cli *selectdb20230522.Client, instanceId *string) (res *selectdb20230522.DescribeSecurityIPListResponseBody) {
	request := &selectdb20230522.DescribeSecurityIPListRequest{
		DBInstanceId: instanceId,
	}

	resp, err := cli.DescribeSecurityIPListWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeSecurityIPListWithOptions error", zap.Error(err))
		return
	}

	return resp.Body
}
