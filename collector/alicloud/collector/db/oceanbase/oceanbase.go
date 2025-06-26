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

package oceanbase

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	oceanbasepro20190901 "github.com/alibabacloud-go/oceanbasepro-20190901/v8/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetOceanbaseResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Oceanbase,
		ResourceTypeName:   collector.Oceanbase,
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://api.aliyun.com/product/OceanBasePro`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"ap-southeast-3",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
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
	cli := service.(*collector.Services).Oceanbasepro
	request := &oceanbasepro20190901.DescribeInstancesRequest{}
	runtime := &util.RuntimeOptions{}
	request.PageSize = tea.Int32(10)
	request.PageNumber = tea.Int32(1)
	count := 0
	for {
		resp, err := cli.DescribeInstancesWithOptions(request, runtime)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeInstancesWithOptions error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.Instances {
			res <- &Detail{
				Instance:          i,
				SecurityIpGroups:  describeSecurityIpGroups(ctx, cli, i.InstanceId),
				InstanceSSL:       describeInstanceSSL(ctx, cli, i.InstanceId),
				TenantEncryptions: describeTenantEncryption(ctx, cli, i.InstanceId),
				BackupSet:         describeDataBackupSet(ctx, cli, i.InstanceId),
			}
		}

		count += len(resp.Body.Instances)
		if int32(count) >= *resp.Body.TotalCount {
			break
		}

		*request.PageNumber = *request.PageNumber + 1
	}
	return nil
}

type Detail struct {
	Instance          *oceanbasepro20190901.DescribeInstancesResponseBodyInstances
	SecurityIpGroups  []*oceanbasepro20190901.DescribeSecurityIpGroupsResponseBodySecurityIpGroups
	InstanceSSL       *oceanbasepro20190901.DescribeInstanceSSLResponseBodyInstanceSSL
	TenantEncryptions []*oceanbasepro20190901.DescribeTenantEncryptionResponseBodyTenantEncryptions
	BackupSet         bool
}

// View IP Security Whitelist Group List
func describeSecurityIpGroups(ctx context.Context, cli *oceanbasepro20190901.Client, instanceId *string) (res []*oceanbasepro20190901.DescribeSecurityIpGroupsResponseBodySecurityIpGroups) {
	request := &oceanbasepro20190901.DescribeSecurityIpGroupsRequest{}
	runtime := &util.RuntimeOptions{}
	request.InstanceId = instanceId
	resp, err := cli.DescribeSecurityIpGroupsWithOptions(request, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeSecurityIpGroupsWithOptions error", zap.Error(err))
		return
	}
	return resp.Body.SecurityIpGroups
}

// This interface is used to query the SSL details of the OceanBase cluster.
func describeInstanceSSL(ctx context.Context, cli *oceanbasepro20190901.Client, instanceId *string) (res *oceanbasepro20190901.DescribeInstanceSSLResponseBodyInstanceSSL) {
	request := &oceanbasepro20190901.DescribeInstanceSSLRequest{}
	request.InstanceId = instanceId
	resp, err := cli.DescribeInstanceSSLWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeInstanceSSLWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.InstanceSSL
}

// This interface is used to query tenant encryption information.
func describeTenantEncryption(ctx context.Context, cli *oceanbasepro20190901.Client, instanceId *string) (res []*oceanbasepro20190901.DescribeTenantEncryptionResponseBodyTenantEncryptions) {
	request := &oceanbasepro20190901.DescribeTenantEncryptionRequest{}
	request.InstanceId = instanceId
	resp, err := cli.DescribeTenantEncryptionWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeTenantEncryptionWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.TenantEncryptions
}

// Determine whether to enable backup, without obtaining actual data
func describeDataBackupSet(ctx context.Context, cli *oceanbasepro20190901.Client, instanceId *string) (backupSet bool) {
	request := &oceanbasepro20190901.DescribeDataBackupSetRequest{}
	request.PageSize = tea.Int32(1)
	request.PageNumber = tea.Int32(1)
	request.InstanceId = instanceId
	request.StartTime = tea.String("2022-12-27T16:00:00Z")
	_, err := cli.DescribeDataBackupSetWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeDataBackupSetWithOptions error", zap.Error(err))
		return
	}

	backupSet = true
	return
}
