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
	Role     ram.Role
	Policies []PolicyDetail
}

func GetRoleDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RAM

	request := ram.CreateListRolesRequest()
	request.Scheme = "https"

	for {
		response, err := cli.ListRoles(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListRoles error", zap.Error(err))
			return err
		}
		for _, role := range response.Roles.Role {
			d := RoleDetail{
				Role:     getRole(ctx, cli, role.RoleName),
				Policies: listPoliciesForRole(ctx, cli, role.RoleName),
			}

			res <- d
		}
		if !response.IsTruncated {
			break
		}
		request.Marker = response.Marker
	}

	return nil
}

func getRole(ctx context.Context, cli *ram.Client, name string) ram.Role {
	request := ram.CreateGetRoleRequest()
	request.RoleName = name
	request.Scheme = "https"
	getRoleResponse, err := cli.GetRole(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetRole error", zap.Error(err))
		return ram.Role{}
	}
	return getRoleResponse.Role
}

func listPoliciesForRole(ctx context.Context, cli *ram.Client, name string) (policies []PolicyDetail) {
	request := ram.CreateListPoliciesForRoleRequest()
	request.Scheme = "https"
	request.RoleName = name
	response, err := cli.ListPoliciesForRole(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForRole error", zap.Error(err))
		return nil
	}

	return getPolicyDetails(ctx, cli, response.Policies.Policy, "Role:"+name)
}

func getPolicyDetails(ctx context.Context, cli *ram.Client, policy []ram.Policy, source string) (policies []PolicyDetail) {

	for i := 0; i < len(policy); i++ {
		r := ram.CreateGetPolicyRequest()
		r.Scheme = "https"
		r.PolicyName = policy[i].PolicyName
		r.PolicyType = policy[i].PolicyType
		resp, err := cli.GetPolicy(r)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetPolicy error", zap.Error(err))
			continue
		}
		p := PolicyDetail{
			Policy:               resp.Policy,
			DefaultPolicyVersion: resp.DefaultPolicyVersion,
			Source:               source,
		}
		policies = append(policies, p)
	}

	return policies
}
