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
	"sync"

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
	policyCache := newPolicyDetailCache()

	for {
		response, err := cli.ListRolesWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListRoles error", zap.Error(err))
			return err
		}
		if response == nil || response.Body == nil {
			return nil
		}
		if response.Body.Roles != nil && response.Body.Roles.Role != nil {
			if err := collectRoleDetails(ctx, cli, response.Body.Roles.Role, policyCache, res); err != nil {
				return err
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

func collectRoleDetails(ctx context.Context, cli *ram20150501.Client, roles []*ram20150501.ListRolesResponseBodyRolesRole, policyCache *policyDetailCache, res chan<- any) error {
	sem := make(chan struct{}, ramDetailConcurrency)
	var wg sync.WaitGroup

	for _, role := range roles {
		if role == nil || role.RoleName == nil {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(role *ram20150501.ListRolesResponseBodyRolesRole) {
			defer wg.Done()
			defer func() { <-sem }()

			name := tea.StringValue(role.RoleName)
			d := RoleDetail{
				Role:     getRole(ctx, cli, name),
				Policies: listPoliciesForRole(ctx, cli, name, policyCache),
			}

			select {
			case <-ctx.Done():
			case res <- d:
			}
		}(role)
	}

	wg.Wait()
	return ctx.Err()
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
	if getRoleResponse == nil || getRoleResponse.Body == nil {
		return nil
	}
	return getRoleResponse.Body.Role
}

func listPoliciesForRole(ctx context.Context, cli *ram20150501.Client, name string, policyCache *policyDetailCache) (policies []PolicyDetail) {
	request := &ram20150501.ListPoliciesForRoleRequest{
		RoleName: tea.String(name),
	}
	response, err := cli.ListPoliciesForRoleWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForRole error", zap.Error(err))
		return nil
	}

	if response != nil && response.Body != nil && response.Body.Policies != nil && response.Body.Policies.Policy != nil {
		return getPolicyDetails(ctx, cli, response.Body.Policies.Policy, "Role:"+name, policyCache)
	}
	return nil
}

func getPolicyDetails(ctx context.Context, cli *ram20150501.Client, policy []*ram20150501.ListPoliciesForRoleResponseBodyPoliciesPolicy, source string, policyCache *policyDetailCache) (policies []PolicyDetail) {

	for i := 0; i < len(policy); i++ {
		if policy[i].PolicyName != nil && policy[i].PolicyType != nil {
			if p, ok := policyCache.get(ctx, cli, policy[i].PolicyName, policy[i].PolicyType, source); ok {
				policies = append(policies, p)
			}
		}
	}

	return policies
}
