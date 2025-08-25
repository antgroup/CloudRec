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

package rds

import (
	"context"
	rds20140815 "github.com/alibabacloud-go/rds-20140815/v6/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetRDSResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.RDS,
		ResourceTypeName:   collector.RDS,
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://api.aliyun.com/product/Rds",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.DBInstanceId",
			ResourceName: "$.DBInstance.DBInstanceDescription",
			Address:      "$.DBInstance.ConnectionString",
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
			"ap-southeast-3",
			"ap-northeast-1",
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
	cli := service.(*collector.Services).RDS

	var page int32 = 1
	req := &rds20140815.DescribeDBInstancesRequest{}
	req.RegionId = cli.RegionId
	req.PageNumber = tea.Int32(page)
	req.PageSize = tea.Int32(100)
	count := 0
	for {
		resp, err := cli.DescribeDBInstancesWithOptions(req, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeDBInstancesWithOptions error", zap.Error(err))
			return err
		}
		bd := resp.Body
		count += len(bd.Items.DBInstance)
		for _, i := range resp.Body.Items.DBInstance {
			res <- &Detail{
				DBInstance:               i,
				DBInstanceAttribute:      describeDBInstanceAttribute(ctx, cli, i.DBInstanceId),
				DBInstanceIPArray:        describeDBInstanceIPArrayList(ctx, cli, i.DBInstanceId),
				EcsSecurityGroupRelation: describeSecurityGroupConfiguration(ctx, cli, i.DBInstanceId),
				DBInstanceSSL:            describeDBInstanceSSL(ctx, cli, i.DBInstanceId),
				DBInstanceTDE:            describeDBInstanceTDE(ctx, cli, i.DBInstanceId),
				SQLCollectorPolicy:       describeSQLCollectorPolicy(ctx, cli, i.DBInstanceId),
				BackupPolicy:             describeBackupPolicy(ctx, cli, i.DBInstanceId),
			}
		}
		if count >= int(*bd.TotalRecordCount) || len(bd.Items.DBInstance) == 0 {
			break
		}
		page += 1
		req.PageNumber = tea.Int32(page)
	}
	return nil
}

type Detail struct {
	DBInstance               *rds20140815.DescribeDBInstancesResponseBodyItemsDBInstance
	DBInstanceAttribute      *rds20140815.DescribeDBInstanceAttributeResponseBodyItemsDBInstanceAttribute
	DBInstanceIPArray        []*rds20140815.DescribeDBInstanceIPArrayListResponseBodyItemsDBInstanceIPArray
	EcsSecurityGroupRelation []*rds20140815.DescribeSecurityGroupConfigurationResponseBodyItemsEcsSecurityGroupRelation
	DBInstanceSSL            *rds20140815.DescribeDBInstanceSSLResponseBody
	DBInstanceTDE            *rds20140815.DescribeDBInstanceTDEResponseBody
	SQLCollectorPolicy       *rds20140815.DescribeSQLCollectorPolicyResponseBody
	BackupPolicy             *rds20140815.DescribeBackupPolicyResponseBody
}

// This interface is used to query the backup settings of the RDS instance.
func describeBackupPolicy(ctx context.Context, cli *rds20140815.Client, DBInstanceId *string) (res *rds20140815.DescribeBackupPolicyResponseBody) {
	request := &rds20140815.DescribeBackupPolicyRequest{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeBackupPolicyWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeBackupPolicyWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

// This interface is used to query detailed information of the RDS instance.
func describeDBInstanceAttribute(ctx context.Context, cli *rds20140815.Client, DBInstanceId *string) (res *rds20140815.DescribeDBInstanceAttributeResponseBodyItemsDBInstanceAttribute) {
	request := &rds20140815.DescribeDBInstanceAttributeRequest{}
	runtime := &util.RuntimeOptions{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeDBInstanceAttributeWithOptions(request, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDBInstanceAttributeWithOptions error", zap.Error(err))
		return
	}
	if resp.Body == nil || resp.Body.Items == nil || resp.Body.Items.DBInstanceAttribute == nil ||
		len(resp.Body.Items.DBInstanceAttribute) == 0 {
		return
	}
	return resp.Body.Items.DBInstanceAttribute[0]
}

// This interface is used to query the IP whitelist of the RDS instance.
func describeDBInstanceIPArrayList(ctx context.Context, cli *rds20140815.Client, DBInstanceId *string) (res []*rds20140815.DescribeDBInstanceIPArrayListResponseBodyItemsDBInstanceIPArray) {
	request := &rds20140815.DescribeDBInstanceIPArrayListRequest{}
	runtime := &util.RuntimeOptions{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeDBInstanceIPArrayListWithOptions(request, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceIPArrayListWithOptions error", zap.Error(err))
		return
	}
	return resp.Body.Items.DBInstanceIPArray
}

// This interface is used to query the association information between the specified RDS instance and the ECS security group.
func describeSecurityGroupConfiguration(ctx context.Context, cli *rds20140815.Client, DBInstanceId *string) (res []*rds20140815.DescribeSecurityGroupConfigurationResponseBodyItemsEcsSecurityGroupRelation) {
	request := &rds20140815.DescribeSecurityGroupConfigurationRequest{}
	runtime := &util.RuntimeOptions{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeSecurityGroupConfigurationWithOptions(request, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeSecurityGroupConfigurationWithOptions error", zap.Error(err))
		return
	}
	return resp.Body.Items.EcsSecurityGroupRelation

}

// This interface is used to query the SSL configuration of the RDS instance.
func describeDBInstanceSSL(ctx context.Context, cli *rds20140815.Client, DBInstanceId *string) (res *rds20140815.DescribeDBInstanceSSLResponseBody) {
	request := &rds20140815.DescribeDBInstanceSSLRequest{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeDBInstanceSSLWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceSSLWithOptions error", zap.Error(err))
		return
	}
	return resp.Body

}

// DescribeDBInstanceTDE This interface is used to query the SSL configuration of the RDS instance.
func describeDBInstanceTDE(ctx context.Context, cli *rds20140815.Client, DBInstanceId *string) (res *rds20140815.DescribeDBInstanceTDEResponseBody) {
	request := &rds20140815.DescribeDBInstanceTDERequest{}
	runtime := &util.RuntimeOptions{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeDBInstanceTDEWithOptions(request, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceTDEWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

func describeSQLCollectorPolicy(ctx context.Context, cli *rds20140815.Client, DBInstanceId *string) (res *rds20140815.DescribeSQLCollectorPolicyResponseBody) {
	request := &rds20140815.DescribeSQLCollectorPolicyRequest{}
	request.DBInstanceId = DBInstanceId
	resp, err := cli.DescribeSQLCollectorPolicyWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeSQLCollectorPolicyWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}
