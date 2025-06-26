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
	"github.com/core-sdk/log"
	"context"
	"encoding/json"
	"go.uber.org/zap"
	"net/url"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/cloudrec/aws/collector"
)

// GetRoleResource returns a Role Resource
func GetRoleResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Role,
		ResourceTypeName:   "IAM Role",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html`,
		ResourceDetailFunc: GetRoleDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Role.RoleId",
			ResourceName: "$.Role.RoleName",
		},
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

type RoleDetail struct {

	// The Role includes authorization details
	Role types.RoleDetail

	// Trusted entities
	TrustedEntities map[string]interface{}
}

func GetRoleDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM

	roleDetails, err := describeRoleDetails(ctx, client)
	if err != nil {
		return err
	}

	for _, roleDetail := range roleDetails {
		res <- roleDetail
	}
	return nil
}

func describeRoleDetails(ctx context.Context, c *iam.Client) (roleDetails []RoleDetail, err error) {

	roles, err := getRoleAuthorizationDetails(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("getRoleAuthorizationDetails error", zap.Error(err))
		return nil, err
	}
	for _, role := range roles {
		roleDetails = append(roleDetails, RoleDetail{
			Role:            role,
			TrustedEntities: decodeTrustedEntities(role.AssumeRolePolicyDocument),
		})
	}
	return roleDetails, nil
}

func decodeTrustedEntities(assumeRolePolicyDocument *string) (trustedEntities map[string]interface{}) {
	decodedDocument, err := url.QueryUnescape(*assumeRolePolicyDocument)
	if err != nil {
		return nil
	}

	err = json.Unmarshal([]byte(decodedDocument), &trustedEntities)
	if err != nil {
		return nil
	}
	return trustedEntities
}

func getRoleAuthorizationDetails(ctx context.Context, c *iam.Client) (roleDetailList []types.RoleDetail, err error) {
	input := &iam.GetAccountAuthorizationDetailsInput{
		Filter: []types.EntityType{
			types.EntityTypeRole,
		},
	}
	out, err := c.GetAccountAuthorizationDetails(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccountAuthorizationDetails error", zap.Error(err))
		return nil, err
	}
	roleDetailList = append(roleDetailList, out.RoleDetailList...)
	for out.IsTruncated {
		input.Marker = out.Marker
		out, err = c.GetAccountAuthorizationDetails(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetAccountAuthorizationDetails error", zap.Error(err))
			return nil, err
		}
		roleDetailList = append(roleDetailList, out.RoleDetailList...)
	}

	return roleDetailList, err
}
