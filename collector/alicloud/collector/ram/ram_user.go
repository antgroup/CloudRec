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
	"context"
	ims20190815 "github.com/alibabacloud-go/ims-20190815/v4/client"

	ram20150501 "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
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
	User                 *ram20150501.ListUsersResponseBodyUsersUser
	UserDetail           *ram20150501.GetUserResponseBodyUser
	LoginProfile         *ims20190815.GetLoginProfileResponseBodyLoginProfile
	Groups               []*ram20150501.ListGroupsForUserResponseBodyGroupsGroup
	ConsoleLogin         bool
	Policies             []PolicyDetail
	AccessKeys           []AccessKeyDetail
	ExistActiveAccessKey bool
	CloudAccountId       string
}

type PolicyDetail struct {
	Policy               *ram20150501.GetPolicyResponseBodyPolicy
	DefaultPolicyVersion *ram20150501.GetPolicyResponseBodyDefaultPolicyVersion
	Source               string
}

type AccessKeyDetail struct {
	AccessKey    *ram20150501.ListAccessKeysResponseBodyAccessKeysAccessKey
	LastUsedDate string
}

func GetUserDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RAM
	imsCli := service.(*collector.Services).IMS

	request := &ram20150501.ListUsersRequest{}
	for {
		response, err := cli.ListUsersWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListUsers error", zap.Error(err))
			return err
		}
		for _, i := range response.Body.Users.User {
			//groups := listGroupsForUser(ctx, cli, i.UserName)
			accessKeys := listAccessKeys(ctx, cli, tea.StringValue(i.UserName))
			d := UserDetail{
				User:       i,
				UserDetail: getUser(ctx, cli, tea.StringValue(i.UserName)),
				//Groups:           groups,
				LoginProfile:         getLoginProfile(ctx, imsCli, i.UserId),
				Policies:             listAttachedPolicies(ctx, cli, tea.StringValue(i.UserName), []*ram20150501.ListGroupsForUserResponseBodyGroupsGroup{}),
				AccessKeys:           accessKeys,
				ExistActiveAccessKey: existActiveAccessKey(accessKeys),
				CloudAccountId:       log.GetCloudAccountId(ctx),
			}

			d.ConsoleLogin = d.LoginProfile != nil && d.LoginProfile.Status != nil && *d.LoginProfile.Status == "Active"

			res <- d
		}
		if !tea.BoolValue(response.Body.IsTruncated) {
			break
		}
		request.Marker = response.Body.Marker
	}
	return nil
}

func existActiveAccessKey(keys []AccessKeyDetail) bool {
	for _, k := range keys {
		if tea.StringValue(k.AccessKey.Status) == "Active" {
			return true
		}
	}
	return false
}

func listAttachedPolicies(ctx context.Context, cli *ram20150501.Client, name string, groups []*ram20150501.ListGroupsForUserResponseBodyGroupsGroup) (policies []PolicyDetail) {
	policiesForUser := listPoliciesForUser(ctx, cli, name)
	policies = append(policies, policiesForUser...)
	for _, group := range groups {
		policiesForGroup := listPoliciesForGroup(ctx, cli, tea.StringValue(group.GroupName))
		policies = append(policies, policiesForGroup...)
	}

	return policies
}

func listGroupsForUser(ctx context.Context, cli *ram20150501.Client, username string) (groups []*ram20150501.ListGroupsForUserResponseBodyGroupsGroup) {
	request := &ram20150501.ListGroupsForUserRequest{
		UserName: tea.String(username),
	}
	response, err := cli.ListGroupsForUserWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListGroupsForUser error", zap.Error(err))
		return
	}
	return response.Body.Groups.Group
}

func getUser(ctx context.Context, cli *ram20150501.Client, username string) (User *ram20150501.GetUserResponseBodyUser) {
	request := &ram20150501.GetUserRequest{
		UserName: tea.String(username),
	}
	response, err := cli.GetUserWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetUser error", zap.Error(err))
		return
	}
	return response.Body.User
}

func getLoginProfile(ctx context.Context, cli *ims20190815.Client, userId *string) (LoginProfile *ims20190815.GetLoginProfileResponseBodyLoginProfile) {
	userPrincipalInfo, err := cli.GetUser(&ims20190815.GetUserRequest{
		UserId: userId,
	})
	if err != nil || userPrincipalInfo.Body.User == nil {
		log.CtxLogger(ctx).Warn("GetUser error", zap.Error(err))
		return
	}

	request := &ims20190815.GetLoginProfileRequest{
		UserPrincipalName: userPrincipalInfo.Body.User.UserPrincipalName,
	}

	response, err := cli.GetLoginProfile(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetLoginProfile error", zap.Error(err))
		return
	}
	return response.Body.LoginProfile
}

// query ram user policies
func listPoliciesForUser(ctx context.Context, cli *ram20150501.Client, username string) (policies []PolicyDetail) {
	request := &ram20150501.ListPoliciesForUserRequest{
		UserName: tea.String(username),
	}
	response, err := cli.ListPoliciesForUserWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForUser error", zap.Error(err))
		return
	}

	return getPolicyDetailsForUser(ctx, cli, response.Body.Policies.Policy, "User:"+username)
}

func getPolicyDetailsForUser(ctx context.Context, cli *ram20150501.Client, policy []*ram20150501.ListPoliciesForUserResponseBodyPoliciesPolicy, source string) (policies []PolicyDetail) {
	for i := 0; i < len(policy); i++ {
		if policy[i].PolicyName != nil && policy[i].PolicyType != nil {
			r := &ram20150501.GetPolicyRequest{
				PolicyName: policy[i].PolicyName,
				PolicyType: policy[i].PolicyType,
			}
			resp, err := cli.GetPolicyWithOptions(r, collector.RuntimeObject)
			if err != nil {
				log.CtxLogger(ctx).Warn("GetPolicy error", zap.Error(err))
				continue
			}
			p := PolicyDetail{
				Policy:               resp.Body.Policy,
				DefaultPolicyVersion: resp.Body.DefaultPolicyVersion,
				Source:               source,
			}
			policies = append(policies, p)
		}
	}
	return policies
}

// query AK
func listAccessKeys(ctx context.Context, cli *ram20150501.Client, username string) (accessKeys []AccessKeyDetail) {
	request := &ram20150501.ListAccessKeysRequest{
		UserName: tea.String(username),
	}
	response, err := cli.ListAccessKeysWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAccessKeys error", zap.Error(err))
		return
	}
	for i := 0; i < len(response.Body.AccessKeys.AccessKey); i++ {
		accessKey := response.Body.AccessKeys.AccessKey[i]
		// query AK last used time
		r := &ram20150501.GetAccessKeyLastUsedRequest{
			UserAccessKeyId: accessKey.AccessKeyId,
			UserName:        tea.String(username),
		}
		resp, err := cli.GetAccessKeyLastUsedWithOptions(r, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetAccessKeyLastUsed error", zap.Error(err))
			continue
		}

		d := AccessKeyDetail{
			AccessKey:    accessKey,
			LastUsedDate: tea.StringValue(resp.Body.AccessKeyLastUsed.LastUsedDate),
		}
		accessKeys = append(accessKeys, d)

	}
	return accessKeys
}
