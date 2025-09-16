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
)

// GetUserResource returns a User Resource
func GetUserResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.User,
		ResourceTypeName:   "User",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html`,
		ResourceDetailFunc: GetUserDetail,
		RowField: schema.RowField{
			ResourceId:   "$.User.Arn",
			ResourceName: "$.User.UserName",
		},
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

// UserDetail aggregates all information for a single IAM user.
type UserDetail struct {
	User             types.User
	AttachedPolicies []types.AttachedPolicy
	InlinePolicies   []string
	MFADevices       []types.MFADevice
	AccessKeys       []types.AccessKeyMetadata
	LoginProfile     *iam.GetLoginProfileOutput
	Tags             []types.Tag
}

// GetUserDetail fetches the details for all IAM users.
func GetUserDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM

	users, err := listUsers(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list users", zap.Error(err))
		return err
	}

	for _, user := range users {
		attachedPolicies := listAttachedUserPolicies(ctx, client, user.UserName)

		inlinePolicies := listUserPolicies(ctx, client, user.UserName)

		mfaDevices := listMFADevices(ctx, client, user.UserName)

		accessKeys := listAccessKeys(ctx, client, user.UserName)

		tags := listUserTags(ctx, client, user.UserName)

		loginProfile := getLoginProfile(ctx, client, user.UserName)

		res <- &UserDetail{
			User:             user,
			AttachedPolicies: attachedPolicies,
			InlinePolicies:   inlinePolicies,
			MFADevices:       mfaDevices,
			AccessKeys:       accessKeys,
			LoginProfile:     loginProfile,
			Tags:             tags,
		}
	}

	return nil
}

// listUsers retrieves all IAM users.
func listUsers(ctx context.Context, c *iam.Client) ([]types.User, error) {
	var users []types.User
	paginator := iam.NewListUsersPaginator(c, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		users = append(users, page.Users...)
	}
	return users, nil
}

// listAttachedUserPolicies retrieves all managed policies attached to a user.
func listAttachedUserPolicies(ctx context.Context, c *iam.Client, userName *string) []types.AttachedPolicy {
	var policies []types.AttachedPolicy
	paginator := iam.NewListAttachedUserPoliciesPaginator(c, &iam.ListAttachedUserPoliciesInput{UserName: userName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list attached user policies", zap.String("user", *userName), zap.Error(err))
			return nil
		}
		policies = append(policies, page.AttachedPolicies...)
	}
	return policies
}

// listUserPolicies retrieves all inline policy names for a user.
func listUserPolicies(ctx context.Context, c *iam.Client, userName *string) []string {
	var policies []string
	paginator := iam.NewListUserPoliciesPaginator(c, &iam.ListUserPoliciesInput{UserName: userName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list user inline policies", zap.String("user", *userName), zap.Error(err))
			return nil
		}
		policies = append(policies, page.PolicyNames...)
	}
	return policies
}

// listMFADevices retrieves all MFA devices for a user.
func listMFADevices(ctx context.Context, c *iam.Client, userName *string) []types.MFADevice {
	var devices []types.MFADevice
	paginator := iam.NewListMFADevicesPaginator(c, &iam.ListMFADevicesInput{UserName: userName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list mfa devices", zap.String("user", *userName), zap.Error(err))
			return nil
		}
		devices = append(devices, page.MFADevices...)
	}
	return devices
}

// listAccessKeys retrieves all access key metadata for a user.
func listAccessKeys(ctx context.Context, c *iam.Client, userName *string) []types.AccessKeyMetadata {
	var keys []types.AccessKeyMetadata
	paginator := iam.NewListAccessKeysPaginator(c, &iam.ListAccessKeysInput{UserName: userName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list access keys", zap.String("user", *userName), zap.Error(err))
			return nil
		}
		keys = append(keys, page.AccessKeyMetadata...)
	}
	return keys
}

// getLoginProfile retrieves the login profile for a user.
func getLoginProfile(ctx context.Context, c *iam.Client, userName *string) *iam.GetLoginProfileOutput {
	output, err := c.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: userName})
	if err != nil {
		log.CtxLogger(ctx).Debug("failed to get login profile", zap.String("user", *userName), zap.Error(err))
		return nil
	}
	return output
}

// listUserTags retrieves all tags for a user.
func listUserTags(ctx context.Context, c *iam.Client, userName *string) []types.Tag {
	var tags []types.Tag
	paginator := iam.NewListUserTagsPaginator(c, &iam.ListUserTagsInput{UserName: userName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list user tags", zap.String("user", *userName), zap.Error(err))
			return nil
		}
		tags = append(tags, page.Tags...)
	}
	return tags
}
