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

func GetGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM

	groupDetails, err := describeGroupDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeGroupDetails error", zap.Error(err))
		return err
	}

	for _, groupDetail := range groupDetails {
		res <- groupDetail
	}
	return nil
}

func describeGroupDetails(ctx context.Context, c *iam.Client) (groupDetails []GroupDetail, err error) {
	groups, err := getGroupAuthorizationDetails(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("getGroupAuthorizationDetails error", zap.Error(err))
		return nil, err
	}
	for _, group := range groups {
		groupDetails = append(groupDetails, GroupDetail{
			Group: group,
			Users: getGroupUsers(ctx, c, group.GroupName),
		})
	}

	return groupDetails, nil
}

func getGroupUsers(ctx context.Context, c *iam.Client, groupName *string) []types.User {

	getGroupOutput, err := c.GetGroup(ctx, &iam.GetGroupInput{GroupName: groupName})
	if err != nil {
		log.CtxLogger(ctx).Warn("GetGroup error", zap.Error(err))
		return nil
	}
	return getGroupOutput.Users
}

func getGroupAuthorizationDetails(ctx context.Context, c *iam.Client) (groupDetailList []types.GroupDetail, err error) {
	input := &iam.GetAccountAuthorizationDetailsInput{
		Filter: []types.EntityType{
			types.EntityTypeGroup,
		},
	}
	out, err := c.GetAccountAuthorizationDetails(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccountAuthorizationDetails error", zap.Error(err))
		return nil, err
	}
	groupDetailList = append(groupDetailList, out.GroupDetailList...)
	for out.IsTruncated {
		input.Marker = out.Marker
		out, err = c.GetAccountAuthorizationDetails(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetAccountAuthorizationDetails error", zap.Error(err))
			return nil, err
		}
		groupDetailList = append(groupDetailList, out.GroupDetailList...)
	}

	return groupDetailList, err
}
