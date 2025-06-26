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

package iam

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/iam"
	"github.com/baidubce/bce-sdk-go/services/iam/api"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	User         api.UserModel
	LoginProfile *api.GetUserLoginProfileResult
	AccessKeys   []api.AccessKeyModel
	Policies     []api.PolicyModel
	Groups       []api.GroupModel
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.IAM,
		ResourceTypeName:   collector.IAM,
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://cloud.baidu.com/doc/IAM/s/0l9chuj6m`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.User.id",
			ResourceName: "$.User.name",
		},
		Dimension: schema.Global,
	}
}
func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAMClient

	users, err := client.ListUser()
	if err != nil {
		log.CtxLogger(ctx).Error("ListUser error", zap.Error(err))
		return err
	}

	for _, user := range users.Users {
		detail := Detail{
			User:         user,
			LoginProfile: getUserLoginProfile(ctx, client, user.Name),
			AccessKeys:   getUserAccessKey(ctx, client, user.Name),
			Policies:     getUserPolicies(ctx, client, user.Name),
			Groups:       getUserGroups(ctx, client, user.Name),
		}
		res <- detail
	}
	return nil
}

func getUserLoginProfile(ctx context.Context, client *iam.Client, name string) *api.GetUserLoginProfileResult {
	resp, err := client.GetUserLoginProfile(name)
	if err != nil {
		log.CtxLogger(ctx).Warn("getUserLoginProfile error", zap.Error(err))
		return nil
	}
	return resp
}

func getUserAccessKey(ctx context.Context, client *iam.Client, name string) []api.AccessKeyModel {
	resp, err := client.ListAccessKey(name)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAccessKey error", zap.Error(err))
		return nil
	}
	return resp.AccessKeys
}

func getUserGroups(ctx context.Context, client *iam.Client, name string) []api.GroupModel {
	resp, err := client.ListGroupsForUser(name)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListGroupsForUser error", zap.Error(err))
		return nil
	}
	return resp.Groups
}

func getUserPolicies(ctx context.Context, client *iam.Client, name string) []api.PolicyModel {
	resp, err := client.ListUserAttachedPolicies(name)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListUserAttachedPolicies error", zap.Error(err))
		return nil
	}
	return resp.Policies
}
