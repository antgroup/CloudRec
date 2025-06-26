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

package accesscontextmanager

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"cloud.google.com/go/accesscontextmanager/apiv1"
	"cloud.google.com/go/accesscontextmanager/apiv1/accesscontextmanagerpb"
	"context"
	"github.com/cloudrec/gcp/collector"
	"github.com/cloudrec/gcp/collector/cloudresourcemanager"
	"go.uber.org/zap"
	"iter"
)

func GetAccessPolicyResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.AccessPolicy,
		ResourceTypeName:  collector.AccessPolicy,
		ResourceGroupType: constant.CONFIG,
		Desc:              ``,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			ACMSvc := service.(*collector.Services).AccessContextManager
			OrgSvc := service.(*collector.Services).OrganizationsClient
			for organization, err := range cloudresourcemanager.SearchOrganizations(ctx, OrgSvc) {
				if err != nil {
					log.CtxLogger(ctx).Warn("SearchOrganizations error", zap.Error(err))
					return err
				}
				for accessPolicy, err := range ListAccessPolicies(ctx, ACMSvc, organization.Name) {
					if err != nil {
						log.CtxLogger(ctx).Warn("ListAccessPolicies error", zap.Error(err))
						return err
					}
					res <- AccessPolicyDetail{
						AccessPolicy: accessPolicy,
					}
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.AccessPolicy.name",
			ResourceName: "$.AccessPolicy.title",
		},
		Dimension: schema.Global,
	}
}

type AccessPolicyDetail struct {
	AccessPolicy *accesscontextmanagerpb.AccessPolicy
}

func ListAccessPolicies(ctx context.Context, svc *accesscontextmanager.Client, organizationName string) iter.Seq2[*accesscontextmanagerpb.AccessPolicy, error] {

	return svc.ListAccessPolicies(ctx, &accesscontextmanagerpb.ListAccessPoliciesRequest{
		Parent: organizationName,
	}).All()
}
