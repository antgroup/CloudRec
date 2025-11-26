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

	ram20150501 "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetRAMRoleResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.RAMRole,
		ResourceTypeName:   collector.RAMRole,
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://api.aliyun.com/product/Ram`,
		ResourceDetailFunc: GetRoleDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Role.RoleId",
			ResourceName: "$.Role.RoleName",
		},
		Dimension: schema.Global,
	}
}

type RoleDetail struct {
	Role     *ram20150501.GetRoleResponseBodyRole
	Policies []PolicyDetail
}

func GetRoleDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RAM

	request := &ram20150501.ListRolesRequest{}

	for {
		response, err := cli.ListRolesWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListRoles error", zap.Error(err))
			return err
		}
		if response.Body.Roles != nil && response.Body.Roles.Role != nil {
			for _, role := range response.Body.Roles.Role {
				if role.RoleName != nil {
					d := RoleDetail{
						Role:     getRole(ctx, cli, *role.RoleName),
						Policies: listPoliciesForRole(ctx, cli, *role.RoleName),
					}
					res <- d
				}
			}
		}
		if response.Body.IsTruncated == nil || !*response.Body.IsTruncated {
			break
		}
		if response.Body.Marker != nil {
			request.Marker = response.Body.Marker
		}
	}

	return nil
}

func getRole(ctx context.Context, cli *ram20150501.Client, name string) *ram20150501.GetRoleResponseBodyRole {
	request := &ram20150501.GetRoleRequest{
		RoleName: tea.String(name),
	}
	getRoleResponse, err := cli.GetRoleWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetRole error", zap.Error(err))
		return nil
	}
	return getRoleResponse.Body.Role
}

func listPoliciesForRole(ctx context.Context, cli *ram20150501.Client, name string) (policies []PolicyDetail) {
	request := &ram20150501.ListPoliciesForRoleRequest{
		RoleName: tea.String(name),
	}
	response, err := cli.ListPoliciesForRoleWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForRole error", zap.Error(err))
		return nil
	}

	if response.Body.Policies != nil && response.Body.Policies.Policy != nil {
		return getPolicyDetails(ctx, cli, response.Body.Policies.Policy, "Role:"+name)
	}
	return nil
}

func getPolicyDetails(ctx context.Context, cli *ram20150501.Client, policy []*ram20150501.ListPoliciesForRoleResponseBodyPoliciesPolicy, source string) (policies []PolicyDetail) {

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
