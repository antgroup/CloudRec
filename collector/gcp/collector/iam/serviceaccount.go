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
	"github.com/cloudrec/gcp/collector"
	"github.com/turbot/go-kit/types"
	"go.uber.org/zap"
	"google.golang.org/api/iam/v1"
)

func GetIAMServiceAccountResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.IAMServiceAccount,
		ResourceTypeName:  collector.IAMServiceAccount,
		ResourceGroupType: constant.IDENTITY,
		Desc:              `https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).IamService
			projects := service.(*collector.Services).Projects

			for _, project := range projects {
				projectId := project.ProjectId
				pageSize := types.Int64(50)
				resp := svc.Projects.ServiceAccounts.List("projects/" + projectId).PageSize(*pageSize)
				if err := resp.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
					for _, account := range page.Accounts {
						d := ServiceAccountDetail{
							ServiceAccount: account,
							Keys:           getServiceAccountKeys(ctx, svc, projectId, account.Email),
							Policy:         GetIamPolicy(ctx, svc, account.Name),
						}
						res <- d
					}
					return nil
				},
				); err != nil {
					log.CtxLogger(ctx).Warn("listServiceAccount err", zap.Error(err))
					continue
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.ServiceAccount.uniqueId",
			ResourceName: "$.ServiceAccount.displayName",
		},
		Dimension: schema.Global,
	}
}

func getServiceAccountKeys(ctx context.Context, service *iam.Service, projectId string, email string) []*iam.ServiceAccountKey {
	resp, err := service.Projects.ServiceAccounts.Keys.List("projects/" + projectId + "/serviceAccounts/" + email).Do()
	if err != nil {
		log.CtxLogger(ctx).Warn("getServiceAccountKeys err", zap.Error(err))
		return nil
	}
	return resp.Keys
}

type ServiceAccountDetail struct {
	ServiceAccount *iam.ServiceAccount
	Keys           []*iam.ServiceAccountKey
	Policy         *iam.Policy
}

func GetIamPolicy(ctx context.Context, iamService *iam.Service, resourceName string) *iam.Policy {
	policy, err := iamService.Projects.ServiceAccounts.GetIamPolicy(resourceName).Do()
	if err != nil {
		log.CtxLogger(ctx).Warn("GetIamPolicy error", zap.Error(err))
		return nil
	}
	return policy
}
