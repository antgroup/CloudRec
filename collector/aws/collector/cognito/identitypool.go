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
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	ciTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

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

// IdentityPoolDetail aggregates all information for a single Cognito Identity Pool.
type IdentityPoolDetail struct {
	IdentityPool ciTypes.IdentityPoolShortDescription
	Tags         map[string]string
}

// GetIdentityPoolDetail fetches the details for all Cognito Identity Pools in a region.
func GetIdentityPoolDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CognitoIdentity

	identityPools, err := listIdentityPools(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Cognito Identity Pools", zap.Error(err))
		return err
	}

	for _, identityPool := range identityPools {
		tags, err := listIdentityPoolTags(ctx, client, identityPool.IdentityPoolId)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list tags for identity pool", zap.String("identityPoolId", *identityPool.IdentityPoolId), zap.Error(err))
		}
		res <- &IdentityPoolDetail{
			IdentityPool: identityPool,
			Tags:         tags,
		}
	}

	return nil
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
