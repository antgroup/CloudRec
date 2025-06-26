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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/cloudrec/aws/collector"
	"go.uber.org/zap"
	"time"
)

// GetUserResource returns a User Resource
func GetUserResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.User,
		ResourceTypeName:   "IAM User",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html`,
		ResourceDetailFunc: GetUserDetail,
		RowField: schema.RowField{
			ResourceId:   "$.User.UserId",
			ResourceName: "$.User.UserName",
		},
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

type UserDetail struct {
	User          types.User
	UserAttribute *types.User
	LoginProfile  *types.LoginProfile
	AccessKeys    []AccessKeyDetail
	MFADevices    []types.MFADevice
	UserPolicies  []Policy
}

type Policy struct {
	Policy        *types.Policy
	PolicyVersion *types.PolicyVersion
}

type AccessKeyDetail struct {
	AccessKeyId       *string
	CreateDate        *time.Time
	Status            types.StatusType
	UserName          *string
	AccessKeyLastUsed *types.AccessKeyLastUsed
}

func GetUserDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM
	ctx = context.TODO()
	users, err := listUsers(ctx, client)
	if err != nil {
		return nil
	}

	for _, user := range users {
		res <- &UserDetail{
			User:          user,
			UserAttribute: getUser(ctx, client, user.UserName),
			LoginProfile:  getLoginProfile(ctx, client, user.UserName),
			AccessKeys:    listAccessKeys(ctx, client, user.UserName),
			MFADevices:    listMFADevices(ctx, client, user.UserName),
			UserPolicies:  listUserPolicies(ctx, client, user.UserName),
		}
	}

	return nil
}

func listUserPolicies(ctx context.Context, c *iam.Client, userName *string) (userPolicies []Policy) {
	policyArnList := listAttachedUserPolicies(ctx, c, userName)
	for _, policyArn := range policyArnList {
		// retrieve specified managed policy
		getPolicyOutput, err := c.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: policyArn,
		})
		if err != nil {
			log.CtxLogger(ctx).Warn("GetPolicy error", zap.Error(err))
			return nil
		}
		userPolicies = append(userPolicies, Policy{
			Policy:        getPolicyOutput.Policy,
			PolicyVersion: getPolicyVersion(ctx, c, getPolicyOutput.Policy),
		})
	}

	return userPolicies
}

func getPolicyVersion(ctx context.Context, c *iam.Client, metadata *types.Policy) *types.PolicyVersion {
	getPolicyVersionOutput, err := c.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: metadata.Arn,
		VersionId: metadata.DefaultVersionId,
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("GetUserPolicyVersion error", zap.Error(err))
		return nil
	}
	return getPolicyVersionOutput.PolicyVersion
}

func listAttachedUserPolicies(ctx context.Context, c *iam.Client, userName *string) (policyArnList []*string) {
	// AttachedUserPolicies
	listAttachedUserPoliciesOutput, err := c.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: userName})
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAttachedUserPolicies error", zap.Error(err))
		return nil
	}
	for _, attachedPolicy := range listAttachedUserPoliciesOutput.AttachedPolicies {
		policyArnList = append(policyArnList, attachedPolicy.PolicyArn)
	}
	return policyArnList
}

func listUsers(ctx context.Context, c *iam.Client) (users []types.User, err error) {
	userInput := &iam.ListUsersInput{}
	userOutput, err := c.ListUsers(ctx, userInput)
	if err != nil {
		log.CtxLogger(ctx).Error("ListUsers error", zap.Error(err))
		return nil, err
	}
	users = append(users, userOutput.Users...)
	for userOutput.IsTruncated {
		userInput.Marker = userOutput.Marker
		userOutput, err = c.ListUsers(ctx, userInput)
		if err != nil {
			log.CtxLogger(ctx).Error("ListUsers error", zap.Error(err))
			return nil, err
		}
		users = append(users, userOutput.Users...)
	}
	return users, nil
}

func listAccessKeys(ctx context.Context, c *iam.Client, userName *string) (accessKeys []AccessKeyDetail) {
	input := &iam.ListAccessKeysInput{
		UserName: userName,
	}
	output, err := c.ListAccessKeys(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Error("ListAccessKeys error", zap.Error(err))
		return nil
	}
	AccessKeyMetadataList := output.AccessKeyMetadata
	for output.IsTruncated {
		input.Marker = output.Marker
		output, err = c.ListAccessKeys(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Error("ListAccessKeys error", zap.Error(err))
			return nil
		}
		AccessKeyMetadataList = append(AccessKeyMetadataList, output.AccessKeyMetadata...)
	}

	for _, accessKey := range AccessKeyMetadataList {
		accessKeys = append(accessKeys, AccessKeyDetail{
			AccessKeyId:       accessKey.AccessKeyId,
			CreateDate:        accessKey.CreateDate,
			Status:            accessKey.Status,
			UserName:          accessKey.UserName,
			AccessKeyLastUsed: getAccessKeyLastUsed(ctx, c, accessKey.AccessKeyId),
		})
	}

	return accessKeys
}

func getAccessKeyLastUsed(ctx context.Context, c *iam.Client, id *string) *types.AccessKeyLastUsed {
	input := &iam.GetAccessKeyLastUsedInput{AccessKeyId: id}
	output, err := c.GetAccessKeyLastUsed(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccessKeyLastUsed failed", zap.Error(err))
		return nil
	}
	return output.AccessKeyLastUsed
}

func getUser(ctx context.Context, c *iam.Client, name *string) *types.User {
	input := &iam.GetUserInput{UserName: name}
	output, err := c.GetUser(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetUser failed", zap.Error(err))
		return nil
	}
	return output.User
}

func getLoginProfile(ctx context.Context, c *iam.Client, name *string) *types.LoginProfile {
	input := &iam.GetLoginProfileInput{UserName: name}
	output, err := c.GetLoginProfile(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("getLoginProfile failed", zap.Error(err))
		return nil
	}
	return output.LoginProfile
}

func listMFADevices(ctx context.Context, c *iam.Client, name *string) (devices []types.MFADevice) {
	input := &iam.ListMFADevicesInput{
		UserName: name,
	}
	output, err := c.ListMFADevices(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("listMFADevices failed", zap.Error(err))
		return nil
	}
	devices = append(devices, output.MFADevices...)
	for output.IsTruncated {
		input.Marker = output.Marker
		output, err = c.ListMFADevices(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListMFADevices failed", zap.Error(err))
			return nil
		}
		devices = append(devices, output.MFADevices...)
	}

	return output.MFADevices
}
