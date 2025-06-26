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

package admin

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudrec/gcp/collector/cloudresourcemanager"
	"github.com/yalp/jsonpath"
	"google.golang.org/api/iterator"

	"github.com/cloudrec/gcp/collector"
	"go.uber.org/zap"
	admin "google.golang.org/api/admin/directory/v1"
)

func GetGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.GoogleGroup,
		ResourceTypeName:  collector.GoogleGroup,
		ResourceGroupType: constant.IDENTITY,
		Desc:              ``,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).Admin
			for organization, err := range cloudresourcemanager.SearchOrganizations(ctx, service.(*collector.Services).OrganizationsClient) {
				if errors.Is(err, iterator.Done) {
					log.CtxLogger(ctx).Warn("SearchOrganizations error", zap.Error(fmt.Errorf("get 0 organization")))
					return err
				}
				if err != nil {
					log.CtxLogger(ctx).Warn("SearchOrganizations error", zap.Error(err))
					return err
				}

				customerId, ok := getCustomerId(ctx, organization).(string)
				if ok {
					if err = svc.Groups.List().Customer(customerId).Pages(ctx, func(resp *admin.Groups) error {
						for _, group := range resp.Groups {
							res <- GroupDetail{
								Group: group,
							}
						}
						return nil
					},
					); err != nil {
						log.CtxLogger(ctx).Warn(fmt.Sprintf("ListGroups error in", organization.DisplayName), zap.Error(err))
					}
				} else {
					log.CtxLogger(ctx).Warn("`DirectoryCustomerId` is not string", zap.Error(err))
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Group.id",
			ResourceName: "$.Group.name",
		},
		Dimension: schema.Global,
	}
}

func getCustomerId(ctx context.Context, organization *resourcemanagerpb.Organization) interface{} {
	jsonBytes, err := json.Marshal(organization)
	if err != nil {
		log.CtxLogger(ctx).Warn("json Marshal Organization error", zap.Error(err))
	}

	var o interface{}
	_ = json.Unmarshal(jsonBytes, &o)
	directoryCustomerId, err := jsonpath.Read(o, "$.Owner.DirectoryCustomerId")
	if err != nil {
		log.CtxLogger(ctx).Warn("Read `DirectoryCustomerId` error", zap.Error(err))
	}

	return directoryCustomerId
}

type GroupDetail struct {
	Group *admin.Group
}
