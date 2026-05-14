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
	"strings"
	"sync"

	ims20190815 "github.com/alibabacloud-go/ims-20190815/v4/client"

	ram20150501 "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const ramDetailConcurrency = 8

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

type policyDetailCache struct {
	mu     sync.Mutex
	values map[string]cachedPolicyDetail
}

type cachedPolicyDetail struct {
	Policy               *ram20150501.GetPolicyResponseBodyPolicy
	DefaultPolicyVersion *ram20150501.GetPolicyResponseBodyDefaultPolicyVersion
}

func newPolicyDetailCache() *policyDetailCache {
	return &policyDetailCache{values: map[string]cachedPolicyDetail{}}
}

func (c *policyDetailCache) get(ctx context.Context, cli *ram20150501.Client, policyName *string, policyType *string, source string) (PolicyDetail, bool) {
	if policyName == nil || policyType == nil {
		return PolicyDetail{}, false
	}
	key := tea.StringValue(policyType) + "\x00" + tea.StringValue(policyName)
	c.mu.Lock()
	cached, ok := c.values[key]
	c.mu.Unlock()
	if ok {
		return PolicyDetail{
			Policy:               cached.Policy,
			DefaultPolicyVersion: cached.DefaultPolicyVersion,
			Source:               source,
		}, true
	}

	r := &ram20150501.GetPolicyRequest{
		PolicyName: policyName,
		PolicyType: policyType,
	}
	resp, err := cli.GetPolicyWithOptions(r, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetPolicy error", zap.Error(err))
		return PolicyDetail{}, false
	}
	if resp == nil || resp.Body == nil {
		return PolicyDetail{}, false
	}
	cached = cachedPolicyDetail{
		Policy:               resp.Body.Policy,
		DefaultPolicyVersion: resp.Body.DefaultPolicyVersion,
	}
	c.mu.Lock()
	c.values[key] = cached
	c.mu.Unlock()
	return PolicyDetail{
		Policy:               cached.Policy,
		DefaultPolicyVersion: cached.DefaultPolicyVersion,
		Source:               source,
	}, true
}

func GetUserDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RAM
	imsCli := service.(*collector.Services).IMS

	request := &ram20150501.ListUsersRequest{}
	policyCache := newPolicyDetailCache()
	for {
		response, err := cli.ListUsersWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListUsers error", zap.Error(err))
			return err
		}
		if response == nil || response.Body == nil || response.Body.Users == nil {
			return nil
		}
		if err := collectUserDetails(ctx, cli, imsCli, response.Body.Users.User, policyCache, res); err != nil {
			return err
		}
		if !tea.BoolValue(response.Body.IsTruncated) {
			break
		}
		request.Marker = response.Body.Marker
	}
	return nil
}

func collectUserDetails(ctx context.Context, cli *ram20150501.Client, imsCli *ims20190815.Client, users []*ram20150501.ListUsersResponseBodyUsersUser, policyCache *policyDetailCache, res chan<- any) error {
	sem := make(chan struct{}, ramDetailConcurrency)
	var wg sync.WaitGroup

	for _, user := range users {
		if user == nil {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(user *ram20150501.ListUsersResponseBodyUsersUser) {
			defer wg.Done()
			defer func() { <-sem }()

			username := tea.StringValue(user.UserName)
			accessKeys := listAccessKeys(ctx, cli, username)
			d := UserDetail{
				User:       user,
				UserDetail: getUser(ctx, cli, username),
				//Groups:           groups,
				LoginProfile:         getLoginProfile(ctx, imsCli, user.UserId),
				Policies:             listAttachedPolicies(ctx, cli, username, []*ram20150501.ListGroupsForUserResponseBodyGroupsGroup{}, policyCache),
				AccessKeys:           accessKeys,
				ExistActiveAccessKey: existActiveAccessKey(accessKeys),
				CloudAccountId:       log.GetCloudAccountId(ctx),
			}

			d.ConsoleLogin = d.LoginProfile != nil && d.LoginProfile.Status != nil && *d.LoginProfile.Status == "Active"

			select {
			case <-ctx.Done():
			case res <- d:
			}
		}(user)
	}

	wg.Wait()
	return ctx.Err()
}

func existActiveAccessKey(keys []AccessKeyDetail) bool {
	for _, k := range keys {
		if tea.StringValue(k.AccessKey.Status) == "Active" {
			return true
		}
	}
	return false
}

func listAttachedPolicies(ctx context.Context, cli *ram20150501.Client, name string, groups []*ram20150501.ListGroupsForUserResponseBodyGroupsGroup, policyCache *policyDetailCache) (policies []PolicyDetail) {
	policiesForUser := listPoliciesForUser(ctx, cli, name, policyCache)
	policies = append(policies, policiesForUser...)
	for _, group := range groups {
		policiesForGroup := listPoliciesForGroup(ctx, cli, tea.StringValue(group.GroupName), policyCache)
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
	if response == nil || response.Body == nil || response.Body.Groups == nil {
		return nil
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
	if response == nil || response.Body == nil {
		return nil
	}
	return response.Body.User
}

func getLoginProfile(ctx context.Context, cli *ims20190815.Client, userId *string) (LoginProfile *ims20190815.GetLoginProfileResponseBodyLoginProfile) {
	userPrincipalInfo, err := cli.GetUser(&ims20190815.GetUserRequest{
		UserId: userId,
	})
	if err != nil || userPrincipalInfo == nil || userPrincipalInfo.Body == nil || userPrincipalInfo.Body.User == nil {
		log.CtxLogger(ctx).Warn("GetUser error", zap.Error(err))
		return
	}

	request := &ims20190815.GetLoginProfileRequest{
		UserPrincipalName: userPrincipalInfo.Body.User.UserPrincipalName,
	}

	response, err := cli.GetLoginProfile(request)
	if err != nil {
		if isExpectedMissingLoginProfile(err) {
			log.CtxLogger(ctx).Debug("GetLoginProfile skipped because login profile does not exist")
			return
		}
		log.CtxLogger(ctx).Warn("GetLoginProfile error", zap.Error(err))
		return
	}
	return response.Body.LoginProfile
}

func isExpectedMissingLoginProfile(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "entitynotexist.user.loginprofile") ||
		strings.Contains(message, "login profile does not exist")
}

// query ram user policies
func listPoliciesForUser(ctx context.Context, cli *ram20150501.Client, username string, policyCache *policyDetailCache) (policies []PolicyDetail) {
	request := &ram20150501.ListPoliciesForUserRequest{
		UserName: tea.String(username),
	}
	response, err := cli.ListPoliciesForUserWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForUser error", zap.Error(err))
		return
	}

	if response == nil || response.Body == nil || response.Body.Policies == nil {
		return nil
	}
	return getPolicyDetailsForUser(ctx, cli, response.Body.Policies.Policy, "User:"+username, policyCache)
}

func getPolicyDetailsForUser(ctx context.Context, cli *ram20150501.Client, policy []*ram20150501.ListPoliciesForUserResponseBodyPoliciesPolicy, source string, policyCache *policyDetailCache) (policies []PolicyDetail) {
	for i := 0; i < len(policy); i++ {
		if policy[i].PolicyName != nil && policy[i].PolicyType != nil {
			if p, ok := policyCache.get(ctx, cli, policy[i].PolicyName, policy[i].PolicyType, source); ok {
				policies = append(policies, p)
			}
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
	if response == nil || response.Body == nil || response.Body.AccessKeys == nil {
		return nil
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
		if resp == nil || resp.Body == nil || resp.Body.AccessKeyLastUsed == nil {
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
