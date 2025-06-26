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

func GetGcpUserAccessBindingResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.UserAccessBinding,
		ResourceTypeName:  collector.UserAccessBinding,
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
				for userAccessBinding, err := range ListGcpUserAccessBindings(ctx, ACMSvc, organization.Name) {
					if err != nil {
						log.CtxLogger(ctx).Warn("ListGcpUserAccessBindings error", zap.Error(err))
						return err
					}
					res <- UserAccessBinding{
						UserAccessBinding: userAccessBinding,
						AccessLevels:      getAccessLevels(ctx, ACMSvc, userAccessBinding.AccessLevels),
					}
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.UserAccessBinding.group_key",
			ResourceName: "$.UserAccessBinding.name",
		},
		Dimension: schema.Global,
	}
}

type UserAccessBinding struct {
	UserAccessBinding *accesscontextmanagerpb.GcpUserAccessBinding
	AccessLevels      []*accesscontextmanagerpb.AccessLevel
}

func ListGcpUserAccessBindings(ctx context.Context, svc *accesscontextmanager.Client, orgName string) iter.Seq2[*accesscontextmanagerpb.GcpUserAccessBinding, error] {

	return svc.ListGcpUserAccessBindings(ctx, &accesscontextmanagerpb.ListGcpUserAccessBindingsRequest{
		Parent: orgName,
	}).All()
}

func getAccessLevels(ctx context.Context, svc *accesscontextmanager.Client, AccessLevels []string) (accessLevels []*accesscontextmanagerpb.AccessLevel) {
	for _, accessLevel := range AccessLevels {
		acl, err := svc.GetAccessLevel(ctx, &accesscontextmanagerpb.GetAccessLevelRequest{
			Name: accessLevel,
		})
		if err != nil {
			log.CtxLogger(ctx).Warn("GetAccessLevel error", zap.Error(err))
			return
		}
		accessLevels = append(accessLevels, acl)
	}
	return
}
