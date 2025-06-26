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

package vpc

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/gcp/collector"
	"github.com/turbot/go-kit/types"
	"go.uber.org/zap"
	"google.golang.org/api/vpcaccess/v1"
)

func GetVPCResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.VPC,
		ResourceTypeName:  collector.VPC,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.google.com/vpc/docs/reference/vpcaccess/rest/v1/projects.locations.connectors`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).VpcAccessService
			projects := service.(*collector.Services).Projects

			for _, project := range projects {
				projectId := project.ProjectId

				locations, err := vpcLocationList(ctx, svc, projectId)
				if err != nil || len(locations) == 0 {
					log.CtxLogger(ctx).Warn("listLocationList err", zap.Error(err))
					continue
				}

				pageSize := types.Int64(500)
				for _, location := range locations {
					parent := "projects/" + projectId + "/locations/" + location.Name
					resp := svc.Projects.Locations.Connectors.List(parent).PageSize(*pageSize)
					if err = resp.Pages(ctx, func(page *vpcaccess.ListConnectorsResponse) error {
						for _, item := range page.Connectors {
							d := &Detail{
								Connector: item,
							}
							res <- d
						}
						return nil
					}); err != nil {
						log.CtxLogger(ctx).Warn("GetVPCResource error", zap.Error(err))
						continue
					}
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Connector.name",
			ResourceName: "$.Connector.name",
		},
		Dimension: schema.Global,
	}
}

func vpcLocationList(ctx context.Context, vpcaccessService *vpcaccess.Service, project string) (locations []*vpcaccess.Location, err error) {
	resp := vpcaccessService.Projects.Locations.List("projects/" + project)
	if err = resp.Pages(ctx, func(page *vpcaccess.ListLocationsResponse) error {
		locations = append(locations, page.Locations...)
		return nil
	}); err != nil {
		return
	}
	return

}

type Detail struct {
	Connector *vpcaccess.Connector
}
