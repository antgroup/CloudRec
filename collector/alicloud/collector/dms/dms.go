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

package dms

import (
	"context"
	dms "github.com/alibabacloud-go/dms-enterprise-20181101/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetDMSResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DMS,
		ResourceTypeName:   collector.DMS,
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://api.aliyun.com/product/dms-enterprise",
		ResourceDetailFunc: GetInstanceDetail,
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
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
		},
		RowField: schema.RowField{
			ResourceId:   "$.Tenant.Tid",
			ResourceName: "$.Tenant.TenantName",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).DMS

	request := &dms.ListUserTenantsRequest{}
	result, err := cli.ListUserTenants(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListUserTenants error", zap.Error(err))
		return nil
	}

	for _, t := range result.Body.TenantList {
		res <- Detail{
			Tenant:        t,
			Users:         describeUser(ctx, cli, t.Tid),
			Instances:     describeInstance(ctx, cli, t.Tid),
			SecurityRules: describeStandardGroup(ctx, cli, t.Tid),
		}
	}

	return nil
}

type Detail struct {
	// Tenant information
	Tenant *dms.ListUserTenantsResponseBodyTenantList
	// User information
	Users *dms.ListUsersResponseBodyUserList
	// Instance information
	Instances []*dms.ListInstancesResponseBodyInstanceListInstance
	// Security rule set information
	SecurityRules []*dms.ListStandardGroupsResponseBodyStandardGroupList
}

// Get user information
func describeUser(ctx context.Context, cli *dms.Client, tid *int64) *dms.ListUsersResponseBodyUserList {
	listUsersRequest := &dms.ListUsersRequest{
		Tid: tid,
	}

	result, err := cli.ListUsers(listUsersRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListUsers error", zap.Error(err))
		return nil
	}
	return result.Body.UserList
}

// Get instance information
func describeInstance(ctx context.Context, cli *dms.Client, tid *int64) []*dms.ListInstancesResponseBodyInstanceListInstance {
	pageNumber := int32(1)
	pageSize := int32(100)
	var result []*dms.ListInstancesResponseBodyInstanceListInstance

	for {
		listInstancesRequest := &dms.ListInstancesRequest{
			Tid:        tid,
			PageNumber: &pageNumber,
			PageSize:   &pageSize,
		}

		resp, err := cli.ListInstances(listInstancesRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstances error", zap.Error(err))
			return nil
		}

		if resp.Body.InstanceList == nil || len(resp.Body.InstanceList.Instance) == 0 {
			break
		}

		result = append(result, resp.Body.InstanceList.Instance...)

		if resp.Body.TotalCount == nil || int64(len(result)) >= *resp.Body.TotalCount {
			break
		}

		pageNumber++
	}

	return result
}

// Get security rule set information
func describeStandardGroup(ctx context.Context, cli *dms.Client, tid *int64) []*dms.ListStandardGroupsResponseBodyStandardGroupList {
	listStandardGroupsRequest := &dms.ListStandardGroupsRequest{
		Tid: tid,
	}

	result, err := cli.ListStandardGroups(listStandardGroupsRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListStandardGroups error", zap.Error(err))
		return nil
	}
	return result.Body.StandardGroupList
}
