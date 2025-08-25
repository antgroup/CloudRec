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

package polardb

import (
	"context"
	polardb20170801 "github.com/alibabacloud-go/polardb-20170801/v6/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"time"
)

func GetPolarDBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.PolarDB,
		ResourceTypeName:   collector.PolarDB,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/polardb`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DBCluster.DBClusterId",
			ResourceName: "$.DBCluster.DBClusterDescription",
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
			"me-east-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Polardb
	request := &polardb20170801.DescribeDBClustersRequest{
		RegionId: cli.RegionId,
	}
	request.PageSize = tea.Int32(30)
	request.PageNumber = tea.Int32(1)
	count := 0
	for {
		resp, err := cli.DescribeDBClustersWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeDBClustersWithOptions error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.Items.DBCluster {
			res <- &Detail{
				DBCluster:                  i,
				DBClusterAttribute:         describeDBClusterAttribute(ctx, cli, i.DBClusterId),
				DBClusterSSL:               describeDBClusterSSL(ctx, cli, i.DBClusterId),
				DBClusterTDE:               describeDBClusterTDE(ctx, cli, i.DBClusterId),
				DBClusterAuditLogCollector: describeDBClusterAuditLogCollector(ctx, cli, i.DBClusterId),
				LogBackupPolicy:            describeLogBackupPolicy(ctx, cli, i.DBClusterId),
				DBClusterAccessWhitelist:   describeDBClusterAccessWhitelist(ctx, cli, i.DBClusterId),
				DBClusterEndpoints:         describeDBClusterEndpoints(ctx, cli, i.DBClusterId),
			}
		}

		count += len(resp.Body.Items.DBCluster)
		if int32(count) >= *resp.Body.TotalRecordCount {
			break
		}
		time.Sleep(1000)
		*request.PageNumber = *request.PageNumber + 1
	}
	return nil
}

type Detail struct {
	DBCluster                  *polardb20170801.DescribeDBClustersResponseBodyItemsDBCluster
	DBClusterAttribute         *polardb20170801.DescribeDBClusterAttributeResponseBody
	DBClusterSSL               []*polardb20170801.DescribeDBClusterSSLResponseBodyItems
	DBClusterTDE               *polardb20170801.DescribeDBClusterTDEResponseBody
	DBClusterAuditLogCollector *polardb20170801.DescribeDBClusterAuditLogCollectorResponseBody
	LogBackupPolicy            *polardb20170801.DescribeLogBackupPolicyResponseBody
	DBClusterAccessWhitelist   *polardb20170801.DescribeDBClusterAccessWhitelistResponseBody
	DBClusterEndpoints         []*polardb20170801.DescribeDBClusterEndpointsResponseBodyItems
}

// View the detailed properties of the PolarDB cluster
func describeDBClusterAttribute(ctx context.Context, cli *polardb20170801.Client, DBClusterId *string) (res *polardb20170801.DescribeDBClusterAttributeResponseBody) {
	request := &polardb20170801.DescribeDBClusterAttributeRequest{
		DBClusterId: DBClusterId,
	}
	resp, err := cli.DescribeDBClusterAttributeWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDBClusterAttributeWithOptions error", zap.Error(err))
		return
	}

	return resp.Body
}

// Query the PolarDB cluster SSL settings
func describeDBClusterSSL(ctx context.Context, cli *polardb20170801.Client, DBClusterId *string) (res []*polardb20170801.DescribeDBClusterSSLResponseBodyItems) {
	request := &polardb20170801.DescribeDBClusterSSLRequest{
		DBClusterId: DBClusterId,
	}
	resp, err := cli.DescribeDBClusterSSLWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBClusterSSLWithOptions error", zap.Error(err))
		return
	}
	return resp.Body.Items
}

// This interface is used to query the association information between the specified RDS instance and the ECS security group.
func describeDBClusterTDE(ctx context.Context, cli *polardb20170801.Client, DBClusterId *string) (res *polardb20170801.DescribeDBClusterTDEResponseBody) {
	request := &polardb20170801.DescribeDBClusterTDERequest{
		DBClusterId: DBClusterId,
	}
	resp, err := cli.DescribeDBClusterTDEWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBClusterTDEWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

// Query the SQL collection functions of the PolarDB cluster (such as audit logs, SQL insights, etc.)
func describeDBClusterAuditLogCollector(ctx context.Context, cli *polardb20170801.Client, DBClusterId *string) (res *polardb20170801.DescribeDBClusterAuditLogCollectorResponseBody) {
	request := &polardb20170801.DescribeDBClusterAuditLogCollectorRequest{
		DBClusterId: DBClusterId,
	}
	resp, err := cli.DescribeDBClusterAuditLogCollectorWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBClusterAuditLogCollectorWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

// Query the retention policy of PolarDB cluster log backup
func describeLogBackupPolicy(ctx context.Context, cli *polardb20170801.Client, DBClusterId *string) (res *polardb20170801.DescribeLogBackupPolicyResponseBody) {
	request := &polardb20170801.DescribeLogBackupPolicyRequest{
		DBClusterId: DBClusterId,
	}
	resp, err := cli.DescribeLogBackupPolicyWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeLogBackupPolicyWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

// View the IP whitelist and security groups that are allowed to access the database cluster
func describeDBClusterAccessWhitelist(ctx context.Context, cli *polardb20170801.Client, DBClusterId *string) (res *polardb20170801.DescribeDBClusterAccessWhitelistResponseBody) {
	request := &polardb20170801.DescribeDBClusterAccessWhitelistRequest{
		DBClusterId: DBClusterId,
	}
	resp, err := cli.DescribeDBClusterAccessWhitelistWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBClusterAccessWhitelistWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

// Query the address information of the PolarDB cluster
func describeDBClusterEndpoints(ctx context.Context, cli *polardb20170801.Client, DBClusterId *string) (res []*polardb20170801.DescribeDBClusterEndpointsResponseBodyItems) {
	request := &polardb20170801.DescribeDBClusterEndpointsRequest{
		DBClusterId: DBClusterId,
	}
	resp, err := cli.DescribeDBClusterEndpointsWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBClusterEndpointsWithOptions error", zap.Error(err))
		return
	}
	return resp.Body.Items
}
