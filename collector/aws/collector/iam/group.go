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

// GetGroupResource returns a Group Resource
func GetGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.UserGroup,
		ResourceTypeName:   "User Group",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html`,
		ResourceDetailFunc: GetGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Group.GroupId",
			ResourceName: "$.Group.GroupName",
		},
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

type GroupDetail struct {
	// The Group includes authorization details
	Group types.GroupDetail

	Users []types.User
}

// GetGroupDetail streams each IAM group as the GetAccountAuthorizationDetails
// pagination yields it and its user lookup completes, avoiding the 30s
// consumer idle timeout in core-sdk schema/platform.go when an account has
// many groups.
func GetGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM

	input := &iam.GetAccountAuthorizationDetailsInput{
		Filter: []types.EntityType{
			types.EntityTypeGroup,
		},
	}
	for {
		out, err := client.GetAccountAuthorizationDetails(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetAccountAuthorizationDetails error", zap.Error(err))
			return err
		}
		for _, group := range out.GroupDetailList {
			res <- GroupDetail{
				Group: group,
				Users: getGroupUsers(ctx, client, group.GroupName),
			}
		}
		if !out.IsTruncated {
			return nil
		}
		input.Marker = out.Marker
	}
}

func getGroupUsers(ctx context.Context, c *iam.Client, groupName *string) []types.User {

	getGroupOutput, err := c.GetGroup(ctx, &iam.GetGroupInput{GroupName: groupName})
	if err != nil {
		log.CtxLogger(ctx).Warn("GetGroup error", zap.Error(err))
		return nil
	}
	return getGroupOutput.Users
}
