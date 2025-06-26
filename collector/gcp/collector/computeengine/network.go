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
	"github.com/turbot/go-kit/types"
	"go.uber.org/zap"
	"google.golang.org/api/compute/v1"
)

func GetNetworkResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.Network,
		ResourceTypeName:  collector.Network,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.google.com/compute/docs/reference/rest/v1/networks`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).ComputeService
			projects := service.(*collector.Services).Projects

			for _, project := range projects {
				projectId := project.ProjectId
				pageSize := types.Int64(500)
				resp := svc.Networks.List(projectId).MaxResults(*pageSize)
				if err := resp.Pages(ctx, func(page *compute.NetworkList) error {
					for _, network := range page.Items {
						d := NetworkDetail{
							Network: network,
						}
						res <- d
					}
					return nil
				}); err != nil {
					log.CtxLogger(ctx).Warn("GetNetworkResource error", zap.Error(err))
					continue
				}
			}
			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Network.id",
			ResourceName: "$.Network.name",
		},
		Dimension: schema.Global,
	}
}

type NetworkDetail struct {
	Network *compute.Network
}
