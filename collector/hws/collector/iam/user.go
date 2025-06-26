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

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/cloudrec/hws/collector"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	"go.uber.org/zap"
)

func GetUserResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.IAMUser,
		ResourceTypeName:   "IAM User",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/IAM/doc?api=KeystoneListUsers",
		ResourceDetailFunc: GetUserDetail,
		RowField: schema.RowField{
			ResourceId:   "$.User.id",
			ResourceName: "$.User.name",
		},
		Dimension: schema.Global,
	}
}

type UserDetail struct {
	User                 model.KeystoneListUsersResult
	UserAttribute        *model.ShowUserResult
	Credentials          *[]model.Credentials
	UserGroups           []*UserGroup
	LoginProtects        *model.LoginProtectResult
	DomainPasswordPolicy *model.PasswordPolicyResult
}

type UserGroup struct {
	Group model.KeystoneGroupResult
	Roles *[]model.RoleResult
}

func GetUserDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).IAM

	request := &model.KeystoneListUsersRequest{}
	response, err := cli.KeystoneListUsers(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("KeystoneListUsers error", zap.Error(err))
		return err
	}

	for _, user := range *response.Users {
		res <- &UserDetail{
			User:                 user,
			UserAttribute:        showUser(ctx, cli, user.Id),
			Credentials:          listPermanentAccessKeys(ctx, cli, user.Id),
			DomainPasswordPolicy: getDomainPasswordPolicy(ctx, cli, user.DomainId),
			LoginProtects:        showUserLoginProtect(ctx, cli, user.Id),
		}

	}
	return nil
}

func listPermanentAccessKeys(ctx context.Context, cli *iam.IamClient, id string) (credentials *[]model.Credentials) {
	request := &model.ListPermanentAccessKeysRequest{}
	request.UserId = &id
	response, err := cli.ListPermanentAccessKeys(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPermanentAccessKeys error", zap.Error(err))
		return
	}

	return response.Credentials
}

func getDomainPasswordPolicy(ctx context.Context, cli *iam.IamClient, domainId string) *model.PasswordPolicyResult {
	request := &model.ShowDomainPasswordPolicyRequest{}
	request.DomainId = domainId
	response, err := cli.ShowDomainPasswordPolicy(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ShowDomainPasswordPolicy error", zap.Error(err))
		return nil
	}
	return response.PasswordPolicy
}

func showUser(ctx context.Context, cli *iam.IamClient, id string) (user *model.ShowUserResult) {
	request := &model.ShowUserRequest{}
	request.UserId = id
	response, err := cli.ShowUser(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ShowUser error", zap.Error(err))
		return
	}

	return response.User
}

func showUserLoginProtect(ctx context.Context, cli *iam.IamClient, id string) (LoginProtects *model.LoginProtectResult) {
	request := &model.ShowUserLoginProtectRequest{}
	request.UserId = id
	response, err := cli.ShowUserLoginProtect(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ShowUserLoginProtect error", zap.Error(err))
		return
	}

	return response.LoginProtect
}
