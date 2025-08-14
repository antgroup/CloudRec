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
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	ciTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const maxWorkers = 10

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

// GetIdentityPoolResource returns AWS Cognito Identity Pool resource definition
func GetIdentityPoolResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CognitoIdentityPool,
		ResourceTypeName:   "Cognito Identity Pool",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               "https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_ListIdentityPools.html",
		ResourceDetailFunc: GetIdentityPoolDetail,
		RowField: schema.RowField{
			ResourceId:   "$.IdentityPool.IdentityPoolId",
			ResourceName: "$.IdentityPool.IdentityPoolName",
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

// IdentityPoolDetail aggregates all information for a single Cognito Identity Pool.
type IdentityPoolDetail struct {
	IdentityPool ciTypes.IdentityPoolShortDescription
	Tags         map[string]string
}

// GetUserPoolDetail fetches the details for all Cognito User Pools in a region.
func GetUserPoolDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CognitoIdentityProvider

	userPools, err := listUserPools(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Cognito User Pools", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.UserPoolDescriptionType, len(userPools))

	// Start worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for userPool := range tasks {
				detail := describeUserPoolDetail(ctx, client, userPool)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks
	for _, userPool := range userPools {
		tasks <- userPool
	}
	close(tasks)

	wg.Wait()
	return nil
}

// GetIdentityPoolDetail fetches the details for all Cognito Identity Pools in a region.
func GetIdentityPoolDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CognitoIdentity

	identityPools, err := listIdentityPools(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Cognito Identity Pools", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan ciTypes.IdentityPoolShortDescription, len(identityPools))

	// Start worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for identityPool := range tasks {
				detail := describeIdentityPoolDetail(ctx, client, identityPool)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks
	for _, identityPool := range identityPools {
		tasks <- identityPool
	}
	close(tasks)

	wg.Wait()
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

// listIdentityPools retrieves all Cognito Identity Pools in a region.
func listIdentityPools(ctx context.Context, c *cognitoidentity.Client) ([]ciTypes.IdentityPoolShortDescription, error) {
	var identityPools []ciTypes.IdentityPoolShortDescription
	input := &cognitoidentity.ListIdentityPoolsInput{
		MaxResults: aws.Int32(50),
	}

	paginator := cognitoidentity.NewListIdentityPoolsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		identityPools = append(identityPools, page.IdentityPools...)
	}
	return identityPools, nil
}

// describeUserPoolDetail fetches all details for a single user pool.
func describeUserPoolDetail(ctx context.Context, client *cognitoidentityprovider.Client, userPool types.UserPoolDescriptionType) *UserPoolDetail {
	var wg sync.WaitGroup
	var userPoolClients []types.UserPoolClientDescription
	var users []types.UserType
	tags := make(map[string]string)

	// Copy the user pool to avoid race conditions
	userPoolCopy := userPool

	wg.Add(3)

	go func() {
		defer wg.Done()
		userPoolClients, _ = listUserPoolClients(ctx, client, userPoolCopy.Id)
	}()

	go func() {
		defer wg.Done()
		users, _ = listUsers(ctx, client, userPoolCopy.Id)
	}()

	go func() {
		defer wg.Done()
		tags, _ = listUserPoolTags(ctx, client, userPoolCopy.Id)
	}()

	wg.Wait()

	return &UserPoolDetail{
		UserPool:        userPoolCopy,
		UserPoolClients: userPoolClients,
		Users:           users,
		Tags:            tags,
	}
}

// describeIdentityPoolDetail fetches all details for a single identity pool.
func describeIdentityPoolDetail(ctx context.Context, client *cognitoidentity.Client, identityPool ciTypes.IdentityPoolShortDescription) *IdentityPoolDetail {
	var tags map[string]string

	// Copy the identity pool to avoid race conditions
	identityPoolCopy := identityPool

	// Get tags
	tags, _ = listIdentityPoolTags(ctx, client, identityPoolCopy.IdentityPoolId)

	return &IdentityPoolDetail{
		IdentityPool: identityPoolCopy,
		Tags:         tags,
	}
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

// listIdentityPoolTags retrieves tags for a single identity pool.
func listIdentityPoolTags(ctx context.Context, c *cognitoidentity.Client, identityPoolId *string) (map[string]string, error) {
	input := &cognitoidentity.ListTagsForResourceInput{
		ResourceArn: identityPoolId,
	}
	output, err := c.ListTagsForResource(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for identity pool", zap.String("identityPoolId", *identityPoolId), zap.Error(err))
		return make(map[string]string), err
	}

	tags := make(map[string]string)
	for key, value := range output.Tags {
		tags[key] = value
	}
	return tags, nil
}
