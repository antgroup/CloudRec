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

package mongodb

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	dds20151201 "github.com/alibabacloud-go/dds-20151201/v8/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetMongoDBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MongoDB,
		ResourceTypeName:   collector.MongoDB,
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://api.aliyun.com/product/Dds",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.DBInstanceId",
			ResourceName: "$.DBInstance.RegionId",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-nanjing",
			"cn-fuzhou",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"cn-wuhan-lr",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-zhengzhou-jva",
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
	cli := service.(*collector.Services).MongoDB

	request := &dds20151201.DescribeDBInstancesRequest{}
	request.PageSize = tea.Int32(30)
	request.PageNumber = tea.Int32(1)
	count := 0
	for {
		resp, err := cli.DescribeDBInstancesWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeDBInstancesWithOptions error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.DBInstances.DBInstance {
			res <- &Detail{
				DBInstance:             i,
				DBInstanceAttribute:    describeDBInstanceAttribute(ctx, cli, i.DBInstanceId),
				LogAuditStatus:         describeAuditPolicy(ctx, cli, i.DBInstanceId),
				DBInstanceSSL:          describeDBInstanceSSL(ctx, cli, i.DBInstanceId),
				TDEInfo:                describeDBInstanceTDEInfo(ctx, cli, i.DBInstanceId),
				SecurityIpGroups:       describeSecurityIps(ctx, cli, i.DBInstanceId),
				RdsEcsSecurityGroupRel: describeSecurityGroupConfiguration(ctx, cli, i.DBInstanceId),
			}
		}

		count += len(resp.Body.DBInstances.DBInstance)
		if int32(count) >= *resp.Body.TotalCount {
			break
		}

		*request.PageNumber = *request.PageNumber + 1
	}
	return nil
}

type Detail struct {
	DBInstance             *dds20151201.DescribeDBInstancesResponseBodyDBInstancesDBInstance
	DBInstanceAttribute    *dds20151201.DescribeDBInstanceAttributeResponseBodyDBInstancesDBInstance
	LogAuditStatus         *string
	DBInstanceSSL          *dds20151201.DescribeDBInstanceSSLResponseBody
	TDEInfo                *dds20151201.DescribeDBInstanceTDEInfoResponseBody
	SecurityIpGroups       []*dds20151201.DescribeSecurityIpsResponseBodySecurityIpGroupsSecurityIpGroup
	RdsEcsSecurityGroupRel []*dds20151201.DescribeSecurityGroupConfigurationResponseBodyItemsRdsEcsSecurityGroupRel
}

// DescribeAuditPolicy Check whether the audit log of the MongoDB instance is enabled
func describeAuditPolicy(ctx context.Context, cli *dds20151201.Client, DBInstanceId *string) (logAuditStatus *string) {
	request := &dds20151201.DescribeAuditPolicyRequest{
		DBInstanceId: DBInstanceId,
	}
	resp, err := cli.DescribeAuditPolicyWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAuditPolicyWithOptions error", zap.Error(err))
		return
	}
	return resp.Body.LogAuditStatus
}

// Query the SSL configuration details of the MongoDB instance
func describeDBInstanceSSL(ctx context.Context, cli *dds20151201.Client, DBInstanceId *string) (body *dds20151201.DescribeDBInstanceSSLResponseBody) {
	request := &dds20151201.DescribeDBInstanceSSLRequest{
		DBInstanceId: DBInstanceId,
	}
	resp, err := cli.DescribeDBInstanceSSLWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceSSLWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

// Query the information of the cloud database MongoDB instance
func describeDBInstanceAttribute(ctx context.Context, cli *dds20151201.Client, DBInstanceId *string) (detail *dds20151201.DescribeDBInstanceAttributeResponseBodyDBInstancesDBInstance) {
	request := &dds20151201.DescribeDBInstanceAttributeRequest{
		DBInstanceId: DBInstanceId,
	}
	resp, err := cli.DescribeDBInstanceAttributeWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceAttributeWithOptions error", zap.Error(err))
		return
	}
	if resp.Body.DBInstances.DBInstance == nil || len(resp.Body.DBInstances.DBInstance) == 0 {
		return
	}
	return resp.Body.DBInstances.DBInstance[0]
}

// Check whether the transparent data encryption (TDE) of the MongoDB instance is enabled
func describeDBInstanceTDEInfo(ctx context.Context, cli *dds20151201.Client, DBInstanceId *string) (body *dds20151201.DescribeDBInstanceTDEInfoResponseBody) {
	request := &dds20151201.DescribeDBInstanceTDEInfoRequest{
		DBInstanceId: DBInstanceId,
	}
	resp, err := cli.DescribeDBInstanceTDEInfoWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDBInstanceTDEInfoWithOptions error", zap.Error(err))
		return
	}

	return resp.Body
}

// DescribeSecurityIps 查询MongoDB实例的IP白名单
func describeSecurityIps(ctx context.Context, cli *dds20151201.Client, DBInstanceId *string) (res []*dds20151201.DescribeSecurityIpsResponseBodySecurityIpGroupsSecurityIpGroup) {
	request := &dds20151201.DescribeSecurityIpsRequest{
		DBInstanceId: DBInstanceId,
		ShowHDMIps:   tea.Bool(true),
	}
	resp, err := cli.DescribeSecurityIpsWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeSecurityIpsWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.SecurityIpGroups.SecurityIpGroup
}

// Query the IP whitelist of the MongoDB instance
func describeSecurityGroupConfiguration(ctx context.Context, cli *dds20151201.Client, DBInstanceId *string) (res []*dds20151201.DescribeSecurityGroupConfigurationResponseBodyItemsRdsEcsSecurityGroupRel) {
	request := &dds20151201.DescribeSecurityGroupConfigurationRequest{
		DBInstanceId: DBInstanceId,
	}
	resp, err := cli.DescribeSecurityGroupConfigurationWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeSecurityGroupConfigurationWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.Items.RdsEcsSecurityGroupRel
}
