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
	accesscontextmanager "cloud.google.com/go/accesscontextmanager/apiv1"
	"cloud.google.com/go/accesscontextmanager/apiv1/accesscontextmanagerpb"
	"context"
	"github.com/cloudrec/gcp/collector"
	"github.com/cloudrec/gcp/collector/cloudresourcemanager"
	"go.uber.org/zap"
	"iter"
)

func GetPerimeterResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.Perimeter,
		ResourceTypeName:  collector.Perimeter,
		ResourceGroupType: constant.CONFIG,
		Desc:              ``,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			ACMSvc := service.(*collector.Services).AccessContextManager
			OrgSvc := service.(*collector.Services).OrganizationsClient
			defer ACMSvc.Close()
			defer OrgSvc.Close()
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
					for perimeter, err := range ListServicePerimeters(ctx, ACMSvc, accessPolicy.Name) {
						if err != nil {
							log.CtxLogger(ctx).Warn("ListServicePerimeters error", zap.Error(err))
							return err
						}
						res <- PerimeterDetail{
							ServicePerimeter: perimeter,
							AccessPolicy:     accessPolicy,
							AccessLevels:     getPolicyAccessLevels(ctx, ACMSvc, accessPolicy.Name),
						}

					}
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.ServicePerimeter.name",
			ResourceName: "$.ServicePerimeter.title",
		},
		Dimension: schema.Global,
	}
}

type PerimeterDetail struct {
	ServicePerimeter *accesscontextmanagerpb.ServicePerimeter
	AccessPolicy     *accesscontextmanagerpb.AccessPolicy
	AccessLevels     []*accesscontextmanagerpb.AccessLevel
}

func ListServicePerimeters(ctx context.Context, svc *accesscontextmanager.Client, policyName string) iter.Seq2[*accesscontextmanagerpb.ServicePerimeter, error] {

	return svc.ListServicePerimeters(ctx, &accesscontextmanagerpb.ListServicePerimetersRequest{
		Parent: policyName,
	}).All()
}

func getPolicyAccessLevels(ctx context.Context, svc *accesscontextmanager.Client, policyName string) (AccessLevels []*accesscontextmanagerpb.AccessLevel) {
	for accessLevel, err := range ListAccessLevels(ctx, svc, policyName) {
		if err != nil {
			return AccessLevels
		}
		AccessLevels = append(AccessLevels, accessLevel)
	}
	return AccessLevels
}

func ListAccessLevels(ctx context.Context, svc *accesscontextmanager.Client, policyName string) iter.Seq2[*accesscontextmanagerpb.AccessLevel, error] {

	return svc.ListAccessLevels(ctx, &accesscontextmanagerpb.ListAccessLevelsRequest{
		Parent: policyName,
	}).All()
}
