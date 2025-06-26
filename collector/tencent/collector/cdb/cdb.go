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

package cdb

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/tencent/collector"
	cdb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdb/v20170320"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"go.uber.org/zap"
)

func GetDBInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CDB,
		ResourceTypeName:   "CDB Instance",
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://cloud.tencent.com/document/api/236/15872",
		ResourceDetailFunc: ListInstanceResource,
		RowField: schema.RowField{
			ResourceId:   "$.InstanceInfo.InstanceId",
			ResourceName: "$.InstanceInfo.InstanceName",
			Address:      "$.InstanceInfo.WanDomain",
		},
		Dimension: schema.Regional,
	}
}

type DBInstanceDetail struct {
	InstanceInfo  cdb.InstanceInfo
	AuditConfig   *cdb.DescribeAuditConfigResponse
	SecurityGroup []*cdb.SecurityGroup
}

func ListInstanceResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CDB

	request := cdb.NewDescribeDBInstancesRequest()
	request.Limit = common.Uint64Ptr(100)
	request.Offset = common.Uint64Ptr(0)

	var count int64
	for {
		response, err := cli.DescribeDBInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDBInstances error", zap.Error(err))
			return err
		}

		for _, item := range response.Response.Items {
			d := &DBInstanceDetail{
				InstanceInfo:  *item,
				AuditConfig:   describeAuditConfig(ctx, cli, *item.InstanceId),
				SecurityGroup: describeDBSecurityGroups(ctx, cli, *item.InstanceId),
			}
			res <- d
		}

		count += int64(len(response.Response.Items))
		if count == *response.Response.TotalCount {
			break
		}

		*request.Offset += *request.Limit
	}

	return nil
}

func describeAuditConfig(ctx context.Context, cli *cdb.Client, instanceId string) *cdb.DescribeAuditConfigResponse {
	request := cdb.NewDescribeAuditConfigRequest()
	request.InstanceId = common.StringPtr(instanceId)

	response, err := cli.DescribeAuditConfig(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAuditConfig error", zap.Error(err))
		return nil
	}

	return response
}

func describeDBSecurityGroups(ctx context.Context, cli *cdb.Client, instanceId string) []*cdb.SecurityGroup {
	request := cdb.NewDescribeDBSecurityGroupsRequest()
	request.InstanceId = common.StringPtr(instanceId)

	response, err := cli.DescribeDBSecurityGroups(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDBSecurityGroups error", zap.Error(err))
		return nil
	}

	return response.Response.Groups
}
