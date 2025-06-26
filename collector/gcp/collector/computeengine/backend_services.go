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

package computeengine

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/gcp/collector"
	"github.com/cloudrec/gcp/utils"
	"github.com/turbot/go-kit/types"
	"go.uber.org/zap"
	"google.golang.org/api/compute/v1"
)

func GetBackendServiceResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.BackendService,
		ResourceTypeName:  collector.BackendService,
		ResourceGroupType: constant.COMPUTE,
		Desc:              `https://cloud.google.com/compute/docs/reference/rest/v1/backendServices`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services)
			projects := service.(*collector.Services).Projects

			for _, project := range projects {
				projectId := project.ProjectId
				pageSize := types.Int64(50)
				resp := svc.ComputeService.BackendServices.AggregatedList(projectId).MaxResults(*pageSize)
				if err := resp.Pages(ctx, func(page *compute.BackendServiceAggregatedList) error {
					for _, item := range page.Items {
						for _, backendService := range item.BackendServices {
							res <- BackendServiceDetail{
								Item:             backendService,
								SecurityPolicies: getSecurityPolicies(ctx, svc, projectId, utils.ParseValue(backendService.SecurityPolicy)),
							}
						}
					}
					return nil
				}); err != nil {
					log.CtxLogger(ctx).Warn("GetBackendServiceResource error", zap.Error(err))
					continue
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Item.id",
			ResourceName: "$.Item.name",
		},
		Dimension: schema.Global,
	}
}

type BackendServiceDetail struct {
	Item             *compute.BackendService
	SecurityPolicies *compute.SecurityPolicy
}

func getSecurityPolicies(ctx context.Context, svc *collector.Services, project string, securityPolicy string) (securityPolicies *compute.SecurityPolicy) {
	if securityPolicy == "" {
		return
	}

	resp, err := svc.ComputeService.SecurityPolicies.Get(project, securityPolicy).Do()
	if err != nil {
		log.CtxLogger(ctx).Warn("getSecurityPolicies error: %s", zap.Error(err))
		return
	}
	return resp
}
