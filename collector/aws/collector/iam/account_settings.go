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
)

// GetAccountSettingsResource returns a AccountSettings Resource
func GetAccountSettingsResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.AccountSettings,
		ResourceTypeName:   collector.AccountSettings,
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html`,
		ResourceDetailFunc: GetAccountSettingsDetail,
		RowField: schema.RowField{
			ResourceId:   "", // AccountID would be
			ResourceName: "", // AccountID would be
		},
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

type AccountSettingsDetail struct {
	PasswordPolicy types.PasswordPolicy

	AccountSummary map[string]int32

	// todo
	//EnabledFeatures []types.FeatureType
}

func GetAccountSettingsDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM

	accountSettingsDetail, err := describeAccountSettingsDetail(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeAccountSettingsDetail error", zap.Error(err))
		return err
	}

	res <- accountSettingsDetail

	return nil
}

func describeAccountSettingsDetail(ctx context.Context, c *iam.Client) (AccountSettingsDetail, error) {

	passwordPolicy, err := getAccountPasswordPolicy(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("getAccountPasswordPolicy error", zap.Error(err))
		return AccountSettingsDetail{}, err
	}

	accountSummary, err := getAccountSummary(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("getAccountSummary error", zap.Error(err))
		return AccountSettingsDetail{}, err
	}

	return AccountSettingsDetail{
		PasswordPolicy: passwordPolicy,
		AccountSummary: accountSummary,
	}, nil
}

func getAccountSummary(ctx context.Context, c *iam.Client) (map[string]int32, error) {
	input := iam.GetAccountSummaryInput{}
	output, err := c.GetAccountSummary(ctx, &input)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccountSummary error", zap.Error(err))
		return nil, err
	}

	return output.SummaryMap, nil
}

func getAccountPasswordPolicy(ctx context.Context, c *iam.Client) (types.PasswordPolicy, error) {
	input := iam.GetAccountPasswordPolicyInput{}
	output, err := c.GetAccountPasswordPolicy(ctx, &input)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccountPasswordPolicy error", zap.Error(err))
		return types.PasswordPolicy{}, err
	}

	return *output.PasswordPolicy, nil
}
