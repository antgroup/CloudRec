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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"sync"
)

// GetRoleResource returns a Role Resource
func GetRoleResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Role,
		ResourceTypeName:   "Role",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html`,
		ResourceDetailFunc: GetRoleDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Role.Arn",
			ResourceName: "$.Role.RoleName",
		},
		Dimension: schema.Global,
	}
}

// RoleDetail aggregates all information for a single IAM role.
type RoleDetail struct {
	Role             types.Role
	AttachedPolicies []types.AttachedPolicy
	InlinePolicies   []string
	Tags             []types.Tag
}

// GetRoleDetail fetches the details for all IAM roles.
func GetRoleDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM

	roles, err := listRoles(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list roles", zap.Error(err))
		return err
	}

	const numWorkers = 10 // A reasonable number of concurrent workers. Consider making this configurable.
	jobs := make(chan types.Role, len(roles))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				res <- describeRoleDetail(ctx, client, r)
			}
		}()
	}

	for _, role := range roles {
		jobs <- role
	}
	close(jobs)

	wg.Wait()

	return nil
}

// describeRoleDetail fetches all details for a single role.
func describeRoleDetail(ctx context.Context, client *iam.Client, role types.Role) RoleDetail {
	var wg sync.WaitGroup
	var attachedPolicies []types.AttachedPolicy
	var inlinePolicies []string
	var tags []types.Tag

	wg.Add(3)

	go func() {
		defer wg.Done()
		attachedPolicies, _ = listAttachedRolePolicies(ctx, client, role.RoleName)
	}()

	go func() {
		defer wg.Done()
		inlinePolicies, _ = listRolePolicies(ctx, client, role.RoleName)
	}()

	go func() {
		defer wg.Done()
		tags, _ = listRoleTags(ctx, client, role.RoleName)
	}()

	wg.Wait()

	return RoleDetail{
		Role:             role,
		AttachedPolicies: attachedPolicies,
		InlinePolicies:   inlinePolicies,
		Tags:             tags,
	}
}

// listRoles retrieves all IAM roles.
func listRoles(ctx context.Context, c *iam.Client) ([]types.Role, error) {
	var roles []types.Role
	paginator := iam.NewListRolesPaginator(c, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		roles = append(roles, page.Roles...)
	}
	return roles, nil
}

// listAttachedRolePolicies retrieves all managed policies attached to a role.
func listAttachedRolePolicies(ctx context.Context, c *iam.Client, roleName *string) ([]types.AttachedPolicy, error) {
	var policies []types.AttachedPolicy
	paginator := iam.NewListAttachedRolePoliciesPaginator(c, &iam.ListAttachedRolePoliciesInput{RoleName: roleName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list attached role policies", zap.String("role", *roleName), zap.Error(err))
			return nil, err
		}
		policies = append(policies, page.AttachedPolicies...)
	}
	return policies, nil
}

// listRolePolicies retrieves all inline policy names for a role.
func listRolePolicies(ctx context.Context, c *iam.Client, roleName *string) ([]string, error) {
	var policies []string
	paginator := iam.NewListRolePoliciesPaginator(c, &iam.ListRolePoliciesInput{RoleName: roleName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list role inline policies", zap.String("role", *roleName), zap.Error(err))
			return nil, err
		}
		policies = append(policies, page.PolicyNames...)
	}
	return policies, nil
}

// listRoleTags retrieves all tags for a role.
func listRoleTags(ctx context.Context, c *iam.Client, roleName *string) ([]types.Tag, error) {
	var tags []types.Tag
	paginator := iam.NewListRoleTagsPaginator(c, &iam.ListRoleTagsInput{RoleName: roleName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list role tags", zap.String("role", *roleName), zap.Error(err))
			return nil, err
		}
		tags = append(tags, page.Tags...)
	}
	return tags, nil
}
