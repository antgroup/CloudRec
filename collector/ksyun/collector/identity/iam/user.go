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
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	iam "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/iam/v20151101"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strconv"
	"strings"
	"time"
)

type GetLoginProfileResponse struct {
	CreateLoginProfileResult struct {
		LoginProfile any `json:"LoginProfile" name:"LoginProfile"`
	} `json:"CreateLoginProfileResult"`
	RequestId *string `json:"RequestId" name:"RequestId"`
}

type GetUserResponse struct {
	GetUserResult any     `json:"GetUserResult"`
	RequestId     *string `json:"RequestId" name:"RequestId"`
}

type Detail struct {
	User                 any
	AttachedUserPolicies []*AttachedPolicy
	Groups               []any
	AccessKeys           []any
	LoginProfile         any
	SsoSettings          any
}

type AttachedPolicy struct {
	Policy   any
	Document *string
}

func GetIAMUserResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.IAMUser,
		ResourceTypeName:  collector.IAMUser,
		ResourceGroupType: constant.IDENTITY,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/1/1083`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).IAM
			request := iam.NewListUsersRequest()
			size := 100
			request.MaxItems = common.IntPtr(size)

			for {
				responseStr := cli.ListUsersWithContext(ctx, request)
				collector.ShowResponse(ctx, "IAM User", "ListUsers", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListUsers error", zap.Error(err))
					return err
				}

				response := iam.NewListUsersResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListUsers decode error", zap.Error(err))
					return err
				}
				if len(response.ListUserResult.Users.Member) == 0 {
					break
				}

				ssoSettings := getUserSsoSettings(ctx, cli)
				for i := range response.ListUserResult.Users.Member {
					item := &response.ListUserResult.Users.Member[i]
					user, e := getUser(ctx, cli, item.UserName)
					if e != nil {
						continue
					}
					res <- Detail{
						User:                 user,
						AttachedUserPolicies: listAttachedUserPolicies(ctx, cli, item.UserName),
						Groups:               listGroupsForUser(ctx, cli, item.UserName),
						AccessKeys:           listAccessKeys(ctx, cli, item.UserName),
						LoginProfile:         getLoginProfile(ctx, cli, item.UserName),
						SsoSettings:          ssoSettings,
					}
					time.Sleep(200 * time.Millisecond)
				}
				if response.ListUserResult.Marker == nil || len(response.ListUserResult.Users.Member) < size {
					break
				}
				request.Marker = response.ListUserResult.Marker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.User.UserId",
			ResourceName: "$.User.UserName",
		},
		Regions: []string{
			"cn-beijing-6",  // 华北1（北京）
			"cn-shanghai-2", // 华东1（上海）
		},
		Dimension: schema.Global,
	}
}

func getUser(ctx context.Context, cli *iam.Client, userName *string) (any, error) {
	request := iam.NewGetUserRequest()
	request.UserName = userName
	user := *userName

	responseStr := cli.GetUserWithContext(ctx, request)
	collector.ShowResponse(ctx, "IAM User", "GetUser", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr), zap.String("user", user)).Warn("IAM User GetUser error", zap.Error(err))
		return nil, err
	}

	response := &GetUserResponse{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr), zap.String("user", user)).Warn("IAM User GetUser decode error", zap.Error(err))
		return nil, err
	}
	return response.GetUserResult, nil
}

func listAttachedUserPolicies(ctx context.Context, cli *iam.Client, userName *string) (ans []*AttachedPolicy) {
	request := iam.NewListAttachedUserPoliciesRequest()
	request.UserName = userName
	size := 100
	request.MaxItems = common.StringPtr(strconv.Itoa(size))

	for {
		responseStr := cli.ListAttachedUserPoliciesWithContext(ctx, request)
		collector.ShowResponse(ctx, "IAM User", "ListAttachedUserPolicies", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListAttachedUserPolicies error", zap.Error(err))
			return nil
		}

		response := iam.NewListAttachedUserPoliciesResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListAttachedUserPolicies decode error", zap.Error(err))
			return nil
		}
		if len(response.ListAttachedUserPoliciesResult.AttachedPolicies.Member) == 0 {
			break
		}

		for i := range response.ListAttachedUserPoliciesResult.AttachedPolicies.Member {
			item := &response.ListAttachedUserPoliciesResult.AttachedPolicies.Member[i]
			ans = append(ans, getPolicy(ctx, cli, item.PolicyKrn))
		}
		if response.ListAttachedUserPoliciesResult.Marker == nil || len(response.ListAttachedUserPoliciesResult.AttachedPolicies.Member) < size {
			break
		}
		request.Marker = response.ListAttachedUserPoliciesResult.Marker
	}

	return ans
}

func getPolicy(ctx context.Context, cli *iam.Client, policyKrn *string) *AttachedPolicy {
	request := iam.NewGetPolicyRequest()
	request.PolicyKrn = policyKrn
	responseStr := cli.GetPolicyWithContext(ctx, request)
	collector.ShowResponse(ctx, "IAM", "GetPolicy", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM GetPolicy error", zap.Error(err))
		return nil
	}

	response := iam.NewGetPolicyResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM GetPolicy decode error", zap.Error(err))
		return nil
	}

	return &AttachedPolicy{
		Policy:   &response.GetPolicyResult.Policy,
		Document: getPolicyDocument(ctx, cli, policyKrn, response.GetPolicyResult.Policy.DefaultVersionId),
	}
}

func getPolicyDocument(ctx context.Context, cli *iam.Client, policyKrn, versionId *string) *string {
	request := iam.NewGetPolicyVersionRequest()
	request.PolicyKrn = policyKrn
	request.VersionId = versionId
	responseStr := cli.GetPolicyVersionWithContext(ctx, request)
	collector.ShowResponse(ctx, "IAM", "GetPolicyVersion", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM GetPolicyVersion error", zap.Error(err))
		return nil
	}

	response := iam.NewGetPolicyVersionResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM GetPolicyVersion decode error", zap.Error(err))
		return nil
	}

	return response.GetPolicyVersionResult.PolicyVersion.Document
}

func listGroupsForUser(ctx context.Context, cli *iam.Client, userName *string) (groupInfos []any) {
	request := iam.NewListGroupsForUserRequest()
	request.UserName = userName
	size := 100
	request.MaxItems = common.StringPtr(strconv.Itoa(size))

	for {
		responseStr := cli.ListGroupsForUserWithContext(ctx, request)
		collector.ShowResponse(ctx, "IAM User", "ListGroupsForUser", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListGroupsForUser error", zap.Error(err))
			return nil
		}

		response := iam.NewListGroupsForUserResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListGroupsForUser decode error", zap.Error(err))
			return nil
		}
		if len(response.ListGroupsForUserResult.Groups.Member) == 0 {
			break
		}

		for i := range response.ListGroupsForUserResult.Groups.Member {
			groupInfos = append(groupInfos, &response.ListGroupsForUserResult.Groups.Member[i])
		}
		if response.ListGroupsForUserResult.Marker == nil || len(response.ListGroupsForUserResult.Groups.Member) < size {
			break
		}

		request.Marker = response.ListGroupsForUserResult.Marker
	}

	return groupInfos
}

func listAccessKeys(ctx context.Context, cli *iam.Client, userName *string) (ans []any) {
	request := iam.NewListAccessKeysRequest()
	request.UserName = userName

	responseStr := cli.ListAccessKeysWithContext(ctx, request)
	collector.ShowResponse(ctx, "IAM User", "ListAccessKeys", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListAccessKeys error", zap.Error(err))
		return nil
	}

	response := iam.NewListAccessKeysResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User ListAccessKeys decode error", zap.Error(err))
		return nil
	}

	for i := range response.ListAccessKeyResult.AccessKeyMetadata.Member {
		ans = append(ans, &response.ListAccessKeyResult.AccessKeyMetadata.Member[i])
	}
	return ans
}

func getLoginProfile(ctx context.Context, cli *iam.Client, userName *string) any {
	request := iam.NewGetLoginProfileRequest()
	request.UserName = userName

	responseStr := cli.GetLoginProfileWithContext(ctx, request)
	collector.ShowResponse(ctx, "IAM User", "GetLoginProfile", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr), zap.String("userName", *userName)).Warn("IAM User GetLoginProfile error", zap.Error(err))
		return nil
	}

	response := &GetLoginProfileResponse{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr), zap.String("userName", *userName)).Warn("IAM User GetLoginProfile decode error", zap.Error(err))
		return nil
	}

	return response.CreateLoginProfileResult.LoginProfile
}

func getUserSsoSettings(ctx context.Context, cli *iam.Client) any {
	request := iam.NewGetUserSsoSettingsRequest()

	responseStr := cli.GetUserSsoSettingsWithContext(ctx, request)
	collector.ShowResponse(ctx, "IAM User", "GetUserSsoSettings", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User GetUserSsoSettings error", zap.Error(err))
		return nil
	}

	response := iam.NewGetUserSsoSettingsResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM User GetUserSsoSettings decode error", zap.Error(err))
		return nil
	}

	return &response.UserSsoSettings
}
