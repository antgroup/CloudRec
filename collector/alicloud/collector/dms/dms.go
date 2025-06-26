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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	dms "github.com/alibabacloud-go/dms-enterprise-20181101/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetDMSResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DMS,
		ResourceTypeName:   "DMS",
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
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).DMS

	resp := describeInstance(ctx, cli)
	if resp == nil || len(resp.Instance) == 0 {
		log.CtxLogger(ctx).Warn("DescribeInstance nil")
		return nil
	}

	res <- Detail{
		User:         describeUser(ctx, cli),
		Instance:     resp,
		SecurityRule: describeStandardGroup(ctx, cli),
	}
	return nil
}

type Detail struct {
	User         *dms.ListUsersResponseBodyUserList
	Instance     *dms.ListInstancesResponseBodyInstanceList
	SecurityRule []*dms.ListStandardGroupsResponseBodyStandardGroupList
}

// Get user information
func describeUser(ctx context.Context, cli *dms.Client) *dms.ListUsersResponseBodyUserList {
	listUsersRequest := &dms.ListUsersRequest{}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListUsersWithOptions(listUsersRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListUsersWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.UserList
}

// Get instance information
func describeInstance(ctx context.Context, cli *dms.Client) *dms.ListInstancesResponseBodyInstanceList {
	listInstancesRequest := &dms.ListInstancesRequest{}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListInstancesWithOptions(listInstancesRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListInstancesWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.InstanceList
}

// Get security rule set information
func describeStandardGroup(ctx context.Context, cli *dms.Client) []*dms.ListStandardGroupsResponseBodyStandardGroupList {
	listStandardGroupsRequest := &dms.ListStandardGroupsRequest{}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListStandardGroupsWithOptions(listStandardGroupsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListStandardGroupsWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.StandardGroupList
}
