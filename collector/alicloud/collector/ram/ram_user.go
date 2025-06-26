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

package ram

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetRAMUserResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.RAMUser,
		ResourceTypeName:   collector.RAMUser,
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://api.aliyun.com/product/Ram`,
		ResourceDetailFunc: GetUserDetail,
		RowField: schema.RowField{
			ResourceId:   "$.User.UserId",
			ResourceName: "$.User.UserName",
		},
		Dimension: schema.Global,
	}
}

type UserDetail struct {
	User                 ram.User
	UserDetail           ram.User
	LoginProfile         ram.LoginProfile
	Groups               []ram.Group
	ConsoleLogin         bool
	Policies             []PolicyDetail
	AccessKeys           []AccessKeyDetail
	ExistActiveAccessKey bool
}

type PolicyDetail struct {
	Policy               ram.Policy
	DefaultPolicyVersion ram.DefaultPolicyVersion
	Source               string
}

type AccessKeyDetail struct {
	AccessKey    ram.AccessKey
	LastUsedDate string
}

func GetUserDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RAM

	request := ram.CreateListUsersRequest()
	request.Scheme = "https"
	for {
		response, err := cli.ListUsers(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListUsers error", zap.Error(err))
			return err
		}
		for _, i := range response.Users.User {
			//groups := listGroupsForUser(ctx, cli, i.UserName)
			accessKeys := listAccessKeys(ctx, cli, i.UserName)
			d := UserDetail{
				User:       i,
				UserDetail: getUser(ctx, cli, i.UserName),
				//Groups:           groups,
				LoginProfile:         getLoginProfile(ctx, cli, i.UserName),
				Policies:             listAttachedPolicies(ctx, cli, i.UserName, []ram.Group{}),
				AccessKeys:           accessKeys,
				ExistActiveAccessKey: existActiveAccessKey(accessKeys),
			}

			d.ConsoleLogin = d.LoginProfile.CreateDate != ""
			res <- d
		}
		if !response.IsTruncated {
			break
		}
		request.Marker = response.Marker
	}
	return nil
}

func existActiveAccessKey(keys []AccessKeyDetail) bool {
	for _, k := range keys {
		if k.AccessKey.Status == "Active" {
			return true
		}
	}
	return false
}

func listAttachedPolicies(ctx context.Context, cli *ram.Client, name string, groups []ram.Group) (policies []PolicyDetail) {
	policiesForUser := listPoliciesForUser(ctx, cli, name)
	policies = append(policies, policiesForUser...)
	for _, group := range groups {
		policiesForGroup := listPoliciesForGroup(ctx, cli, group.GroupName)
		policies = append(policies, policiesForGroup...)
	}

	return policies
}

func listGroupsForUser(ctx context.Context, cli *ram.Client, username string) (groups []ram.Group) {
	request := ram.CreateListGroupsForUserRequest()
	request.Scheme = "https"
	request.UserName = username
	response, err := cli.ListGroupsForUser(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListGroupsForUser error", zap.Error(err))
		return
	}
	return response.Groups.Group
}

func getUser(ctx context.Context, cli *ram.Client, username string) (user ram.User) {
	request := ram.CreateGetUserRequest()
	request.Scheme = "https"
	request.UserName = username
	response, err := cli.GetUser(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetUser error", zap.Error(err))
		return
	}

	return response.User
}

func getLoginProfile(ctx context.Context, cli *ram.Client, username string) (LoginProfile ram.LoginProfile) {
	request := ram.CreateGetLoginProfileRequest()
	request.Scheme = "https"
	request.UserName = username
	response, err := cli.GetLoginProfile(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetLoginProfile error", zap.Error(err))
		return
	}
	return response.LoginProfile
}

// query ram user policies
func listPoliciesForUser(ctx context.Context, cli *ram.Client, username string) (policies []PolicyDetail) {
	request := ram.CreateListPoliciesForUserRequest()
	request.Scheme = "https"
	request.UserName = username
	response, err := cli.ListPoliciesForUser(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForUser error", zap.Error(err))
		return
	}

	return getPolicyDetails(ctx, cli, response.Policies.Policy, "User:"+username)
}

// query AK
func listAccessKeys(ctx context.Context, cli *ram.Client, username string) (accessKeys []AccessKeyDetail) {
	request := ram.CreateListAccessKeysRequest()
	request.Scheme = "https"
	request.UserName = username
	response, err := cli.ListAccessKeys(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAccessKeys error", zap.Error(err))
		return
	}
	for i := 0; i < len(response.AccessKeys.AccessKey); i++ {
		accessKey := response.AccessKeys.AccessKey[i]
		// query AK last used time
		r := ram.CreateGetAccessKeyLastUsedRequest()
		r.Scheme = "https"
		r.UserAccessKeyId = accessKey.AccessKeyId
		r.UserName = username
		resp, err := cli.GetAccessKeyLastUsed(r)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetAccessKeyLastUsed error", zap.Error(err))
			continue
		}

		d := AccessKeyDetail{
			AccessKey:    accessKey,
			LastUsedDate: resp.AccessKeyLastUsed.LastUsedDate,
		}
		accessKeys = append(accessKeys, d)

	}

	return accessKeys
}
