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

package cognito

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetUserPoolResource returns AWS Cognito User Pool resource definition
func GetUserPoolResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CognitoUserPool,
		ResourceTypeName:   "Cognito User Pool",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPools.html",
		ResourceDetailFunc: GetUserPoolDetail,
		RowField: schema.RowField{
			ResourceId:   "$.UserPool.Id",
			ResourceName: "$.UserPool.Name",
		},
		Dimension: schema.Regional,
	}
}

// UserPoolDetail aggregates all information for a single Cognito User Pool.
type UserPoolDetail struct {
	UserPool        types.UserPoolDescriptionType
	UserPoolClients []types.UserPoolClientDescription
	Users           []types.UserType
	Tags            map[string]string
}

// GetUserPoolDetail fetches the details for all Cognito User Pools in a region.
func GetUserPoolDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CognitoIdentityProvider

	userPools, err := listUserPools(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Cognito User Pools", zap.Error(err))
		return err
	}

	for _, userPool := range userPools {
		userPoolClients, err := listUserPoolClients(ctx, client, userPool.Id)
		if err != nil {
			log.CtxLogger(ctx).Error("failed to list user pool clients", zap.String("userPoolId", *userPool.Id), zap.Error(err))
			return err
		}

		users, err := listUsers(ctx, client, userPool.Id)
		if err != nil {
			log.CtxLogger(ctx).Error("failed to list users", zap.String("userPoolId", *userPool.Id), zap.Error(err))
			return err
		}

		tags, err := listUserPoolTags(ctx, client, userPool.Id)
		if err != nil {
			log.CtxLogger(ctx).Error("failed to list user pool tags", zap.String("userPoolId", *userPool.Id), zap.Error(err))
			return err
		}

		res <- &UserPoolDetail{
			UserPool:        userPool,
			UserPoolClients: userPoolClients,
			Users:           users,
			Tags:            tags,
		}
	}

	return nil
}

// listUserPools retrieves all Cognito User Pools in a region.
func listUserPools(ctx context.Context, c *cognitoidentityprovider.Client) ([]types.UserPoolDescriptionType, error) {
	var userPools []types.UserPoolDescriptionType
	input := &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int32(50),
	}

	paginator := cognitoidentityprovider.NewListUserPoolsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		userPools = append(userPools, page.UserPools...)
	}
	return userPools, nil
}

// listUserPoolClients retrieves clients for a single user pool.
func listUserPoolClients(ctx context.Context, c *cognitoidentityprovider.Client, userPoolId *string) ([]types.UserPoolClientDescription, error) {
	var userPoolClients []types.UserPoolClientDescription
	input := &cognitoidentityprovider.ListUserPoolClientsInput{
		UserPoolId: userPoolId,
		MaxResults: aws.Int32(50),
	}

	paginator := cognitoidentityprovider.NewListUserPoolClientsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list user pool clients", zap.String("userPoolId", *userPoolId), zap.Error(err))
			return nil, err
		}
		userPoolClients = append(userPoolClients, page.UserPoolClients...)
	}
	return userPoolClients, nil
}

// listUsers retrieves users for a single user pool.
func listUsers(ctx context.Context, c *cognitoidentityprovider.Client, userPoolId *string) ([]types.UserType, error) {
	var users []types.UserType
	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: userPoolId,
		Limit:      aws.Int32(50),
	}

	paginator := cognitoidentityprovider.NewListUsersPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list users", zap.String("userPoolId", *userPoolId), zap.Error(err))
			return nil, err
		}
		users = append(users, page.Users...)
	}
	return users, nil
}

// listUserPoolTags retrieves tags for a single user pool.
func listUserPoolTags(ctx context.Context, c *cognitoidentityprovider.Client, userPoolId *string) (map[string]string, error) {
	input := &cognitoidentityprovider.ListTagsForResourceInput{
		ResourceArn: userPoolId,
	}
	output, err := c.ListTagsForResource(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for user pool", zap.String("userPoolId", *userPoolId), zap.Error(err))
		return make(map[string]string), err
	}

	tags := make(map[string]string)
	for key, value := range output.Tags {
		tags[key] = value
	}
	return tags, nil
}
