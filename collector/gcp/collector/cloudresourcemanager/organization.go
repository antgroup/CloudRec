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

package cloudresourcemanager

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"context"
	"errors"
	"fmt"
	"google.golang.org/api/iterator"

	"github.com/core-sdk/log"
	"github.com/cloudrec/gcp/collector"
	"go.uber.org/zap"
	"iter"
)

func GetOrganizationResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.Organization,
		ResourceTypeName:  collector.Organization,
		ResourceGroupType: constant.GOVERNANCE,
		Desc:              ``,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).OrganizationsClient

			for organization, err := range SearchOrganizations(ctx, svc) {
				if errors.Is(err, iterator.Done) {
					return fmt.Errorf("get 0 organization")
				}
				if err != nil {
					log.CtxLogger(ctx).Warn("SearchOrganizations error", zap.Error(err))
					return err
				}
				res <- OrganizationDetail{
					Organization: organization,
					IAMPolicy:    getOrgIAMPolicy(ctx, svc, organization.Name),
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Organization.name",
			ResourceName: "$.Organization.display_name",
		},
		Dimension: schema.Global,
	}
}

type OrganizationDetail struct {
	Organization *resourcemanagerpb.Organization
	IAMPolicy    *iampb.Policy
}

func SearchOrganizations(ctx context.Context, svc *resourcemanager.OrganizationsClient) iter.Seq2[*resourcemanagerpb.Organization, error] {

	a := svc.SearchOrganizations(ctx, &resourcemanagerpb.SearchOrganizationsRequest{}).All()
	return a
}

func getOrgIAMPolicy(ctx context.Context, svc *resourcemanager.OrganizationsClient, OrgName string) *iampb.Policy {
	iamPolicy, err := svc.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: OrgName,
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("GetIamPolicy error", zap.Error(err))
		return nil
	}
	return iamPolicy
}
