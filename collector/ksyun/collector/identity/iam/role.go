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
	"strings"
)

type RoleDetail struct {
	Role             any
	AttachedPolicies []*AttachedPolicy
}

func GetIAMRoleResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.IAMRole,
		ResourceTypeName:  collector.IAMRole,
		ResourceGroupType: constant.IDENTITY,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/1/1083`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).IAM
			request := iam.NewListRolesRequest()
			size := 100
			request.MaxItems = common.IntPtr(size)

			for {
				responseStr := cli.ListRolesWithContext(ctx, request)
				collector.ShowResponse(ctx, "IAM Role", "ListRoles", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM Role ListRoles error", zap.Error(err))
					return err
				}

				response := iam.NewListRolesResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM Role ListRoles decode error", zap.Error(err))
					return err
				}
				if len(response.ListRolesResult.Roles.Member) == 0 {
					break
				}

				for i := range response.ListRolesResult.Roles.Member {
					item := &response.ListRolesResult.Roles.Member[i]
					res <- RoleDetail{
						Role:             item,
						AttachedPolicies: listAttachedRolePolicies(ctx, cli, item.RoleName),
					}
				}
				if response.ListRolesResult.Marker == nil || len(response.ListRolesResult.Roles.Member) < size {
					break
				}
				request.Marker = response.ListRolesResult.Marker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Role.RoleId",
			ResourceName: "$.Role.RoleName",
		},
		Regions: []string{
			"cn-beijing-6",  // 华北1（北京）
			"cn-shanghai-2", // 华东1（上海）
		},
		Dimension: schema.Global,
	}
}

func listAttachedRolePolicies(ctx context.Context, cli *iam.Client, roleName *string) (ans []*AttachedPolicy) {
	request := iam.NewListAttachedRolePoliciesRequest()
	request.RoleName = roleName
	request.MaxItems = common.IntPtr(100)

	for {
		responseStr := cli.ListAttachedRolePoliciesWithContext(ctx, request)
		collector.ShowResponse(ctx, "IAM Role", "ListAttachedRolePolicies", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM Role ListAttachedRolePolicies error", zap.Error(err))
			return nil
		}

		response := iam.NewListAttachedRolePoliciesResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("IAM Role ListAttachedRolePolicies decode error", zap.Error(err))
			return nil
		}
		if len(response.ListAttachedRolePoliciesResult.AttachedPolicies.Member) == 0 {
			break
		}

		for i := range response.ListAttachedRolePoliciesResult.AttachedPolicies.Member {
			item := &response.ListAttachedRolePoliciesResult.AttachedPolicies.Member[i]
			ans = append(ans, getPolicy(ctx, cli, item.PolicyKrn))
		}
		if response.ListAttachedRolePoliciesResult.Marker == nil || len(response.ListAttachedRolePoliciesResult.AttachedPolicies.Member) < *request.MaxItems {
			break
		}
		request.Marker = response.ListAttachedRolePoliciesResult.Marker
	}

	return ans
}
