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

package adbmysql

import (
	"context"
	adb20190315 "github.com/alibabacloud-go/adb-20190315/v4/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetAnalyticDBMySQLResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.AnalyticDBMySQL,
		ResourceTypeName:   collector.AnalyticDBMySQL,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/adb`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DBCluster.DBClusterId",
			ResourceName: "$.DBCluster.DBClusterDescription",
			Address:      "$.DBCluster.ConnectionString",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
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
	cli := service.(*collector.Services).AnalyticDBMySQL

	request := &adb20190315.DescribeDBClustersRequest{
		RegionId: cli.RegionId,
	}
	request.PageSize = tea.Int32(30)
	request.PageNumber = tea.Int32(1)

	count := 0
	for {
		resp, err := cli.DescribeDBClustersWithOptions(request, &util.RuntimeOptions{})
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeDBClustersWithOptions error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.Items.DBCluster {
			res <- &Detail{
				DBCluster:          i,
				DBClusterAttribute: describeDBClusterAttribute(ctx, cli, i.DBClusterId),
				IPArray:            describeDBClusterAccessWhiteList(ctx, cli, i.DBClusterId),
			}
		}

		count += len(resp.Body.Items.DBCluster)
		if count >= int(*resp.Body.TotalCount) {
			break
		}

		*request.PageNumber = *resp.Body.PageNumber + 1
	}

	return nil
}

type Detail struct {
	DBCluster          *adb20190315.DescribeDBClustersResponseBodyItemsDBCluster
	DBClusterAttribute *adb20190315.DescribeDBClusterAttributeResponseBodyItemsDBCluster
	IPArray            []*adb20190315.DescribeDBClusterAccessWhiteListResponseBodyItemsIPArray
}

// View the details of the target AnalyticDB MySQL cluster
func describeDBClusterAttribute(ctx context.Context, cli *adb20190315.Client, DBClusterId *string) (detail *adb20190315.DescribeDBClusterAttributeResponseBodyItemsDBCluster) {
	request := &adb20190315.DescribeDBClusterAttributeRequest{}
	request.DBClusterId = DBClusterId
	resp, err := cli.DescribeDBClusterAttributeWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBClusterAttributeWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.Items.DBCluster[0]
}

// View the cluster's IP whitelist
func describeDBClusterAccessWhiteList(ctx context.Context, cli *adb20190315.Client, DBClusterId *string) (IPArray []*adb20190315.DescribeDBClusterAccessWhiteListResponseBodyItemsIPArray) {
	req := &adb20190315.DescribeDBClusterAccessWhiteListRequest{}
	req.DBClusterId = DBClusterId

	resp, err := cli.DescribeDBClusterAccessWhiteList(req)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBClusterAccessWhiteList error", zap.Error(err))
		return
	}
	return resp.Body.Items.IPArray
}
