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

package redis

import (
	"context"
	r_kvstore20150101 "github.com/alibabacloud-go/r-kvstore-20150101/v5/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GeRedisResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Redis,
		ResourceTypeName:   collector.Redis,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/R-kvstore`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.KVStoreInstance.InstanceId",
			ResourceName: "$.KVStoreInstance.InstanceName",
			Address:      "$.KVStoreInstance.ConnectionDomain",
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
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.Redis
	regionId := services.Config.RegionId

	request := &r_kvstore20150101.DescribeInstancesRequest{}
	request.RegionId = regionId
	request.PageSize = tea.Int32(30)
	request.PageNumber = tea.Int32(1)

	count := 0
	for {
		resp, err := cli.DescribeInstancesWithOptions(request, &util.RuntimeOptions{})
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeInstancesWithOptions error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.Instances.KVStoreInstance {
			res <- &Detail{
				KVStoreInstance:     i,
				InstanceNetInfo:     describeDBInstanceNetInfo(ctx, cli, i.InstanceId),
				DBInstanceAttribute: describeInstanceAttribute(ctx, cli, i.InstanceId),
				InstanceSSL:         describeInstanceSSL(ctx, cli, i.InstanceId),
				SecurityIpGroups:    describeSecurityIps(ctx, cli, i.InstanceId),
				BackupPolicy:        describeBackupPolicy(ctx, cli, i.InstanceId),
				AuditLogConfig:      describeAuditLogConfig(ctx, cli, regionId, i.InstanceId),
				TDEStatus:           describeInstanceTDEStatus(ctx, cli, i.InstanceId),
			}
		}

		count += len(resp.Body.Instances.KVStoreInstance)
		if count >= int(*resp.Body.TotalCount) {
			break
		}

		*request.PageNumber = *resp.Body.PageNumber + 1
	}

	return nil
}

type Detail struct {
	endPoint            string
	KVStoreInstance     *r_kvstore20150101.DescribeInstancesResponseBodyInstancesKVStoreInstance
	InstanceNetInfo     []*r_kvstore20150101.DescribeDBInstanceNetInfoResponseBodyNetInfoItemsInstanceNetInfo
	DBInstanceAttribute []*r_kvstore20150101.DescribeInstanceAttributeResponseBodyInstancesDBInstanceAttribute
	InstanceSSL         *r_kvstore20150101.DescribeInstanceSSLResponseBody
	SecurityIpGroups    []*r_kvstore20150101.DescribeSecurityIpsResponseBodySecurityIpGroupsSecurityIpGroup
	BackupPolicy        *r_kvstore20150101.DescribeBackupPolicyResponseBody
	AuditLogConfig      *r_kvstore20150101.DescribeAuditLogConfigResponseBody
	TDEStatus           *string
}

// View the network information of the Redis instance
func describeDBInstanceNetInfo(ctx context.Context, cli *r_kvstore20150101.Client, instanceId *string) (instanceNetInfo []*r_kvstore20150101.DescribeDBInstanceNetInfoResponseBodyNetInfoItemsInstanceNetInfo) {
	request := &r_kvstore20150101.DescribeDBInstanceNetInfoRequest{}
	request.InstanceId = instanceId
	resp, err := cli.DescribeDBInstanceNetInfoWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDBInstanceNetInfoWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.NetInfoItems.InstanceNetInfo
}

// Query the detailed information of the Redis instance
func describeInstanceAttribute(ctx context.Context, cli *r_kvstore20150101.Client, instanceId *string) (dBInstanceAttribute []*r_kvstore20150101.DescribeInstanceAttributeResponseBodyInstancesDBInstanceAttribute) {
	req := &r_kvstore20150101.DescribeInstanceAttributeRequest{}
	req.InstanceId = instanceId

	resp, err := cli.DescribeInstanceAttribute(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstanceAttribute error", zap.Error(err))
		return
	}
	return resp.Body.Instances.DBInstanceAttribute
}

// Check whether TLS (SSL) encryption authentication is enabled on the instance
func describeInstanceSSL(ctx context.Context, cli *r_kvstore20150101.Client, instanceId *string) (body *r_kvstore20150101.DescribeInstanceSSLResponseBody) {
	req := &r_kvstore20150101.DescribeInstanceSSLRequest{}
	req.InstanceId = instanceId
	resp, err := cli.DescribeInstanceSSLWithOptions(req, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstanceSSLWithOptions error", zap.Error(err))
		return
	}
	return resp.Body
}

// Query the IP whitelist of the Redis instance
func describeSecurityIps(ctx context.Context, cli *r_kvstore20150101.Client, instanceId *string) (securityIpGroup []*r_kvstore20150101.DescribeSecurityIpsResponseBodySecurityIpGroupsSecurityIpGroup) {
	req := &r_kvstore20150101.DescribeSecurityIpsRequest{}
	req.InstanceId = instanceId
	resp, err := cli.DescribeSecurityIps(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeSecurityIps error", zap.Error(err))
		return
	}
	return resp.Body.SecurityIpGroups.SecurityIpGroup
}

// DescribeBackupPolicy Query backup policy
func describeBackupPolicy(ctx context.Context, cli *r_kvstore20150101.Client, instanceId *string) (body *r_kvstore20150101.DescribeBackupPolicyResponseBody) {
	req := &r_kvstore20150101.DescribeBackupPolicyRequest{}
	req.InstanceId = instanceId

	resp, err := cli.DescribeBackupPolicy(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeBackupPolicy error", zap.Error(err))
		return
	}
	return resp.Body
}

// Query audit log configuration
func describeAuditLogConfig(ctx context.Context, cli *r_kvstore20150101.Client, regionId, instanceId *string) (Body *r_kvstore20150101.DescribeAuditLogConfigResponseBody) {
	req := &r_kvstore20150101.DescribeAuditLogConfigRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}
	resp, err := cli.DescribeAuditLogConfig(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAuditLogConfig error", zap.Error(err))
		return
	}

	return resp.Body
}

// Check whether TDE encryption is enabled on the instance
func describeInstanceTDEStatus(ctx context.Context, cli *r_kvstore20150101.Client, instanceId *string) (TDEStatus *string) {
	req := &r_kvstore20150101.DescribeInstanceTDEStatusRequest{
		InstanceId: instanceId,
	}

	resp, err := cli.DescribeInstanceTDEStatusWithOptions(req, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstanceTDEStatusWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.TDEStatus
}
