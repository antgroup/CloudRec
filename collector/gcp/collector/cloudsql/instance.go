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

package cloudsql

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/gcp/collector"
	"go.uber.org/zap"
	"google.golang.org/api/sqladmin/v1"
)

func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.CloudSQLInstance,
		ResourceTypeName:  collector.CloudSQLInstance,
		ResourceGroupType: constant.DATABASE,
		Desc:              `https://cloud.google.com/sql/docs/mysql/apis`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).CloudSQL
			projects := service.(*collector.Services).Projects

			for _, project := range projects {
				projectId := project.ProjectId
				resp, err := svc.Instances.List(projectId).Do()
				if err != nil {
					log.CtxLogger(ctx).Warn("Unable to retrieve cloud sql instances:", zap.Error(err))
					continue
				}
				for _, instance := range resp.Items {
					res <- InstanceDetail{
						DatabaseInstance: instance,
					}
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.DatabaseInstance.dnsName",
			ResourceName: "$.DatabaseInstance.name",
		},
		Dimension: schema.Global,
	}
}

type InstanceDetail struct {
	DatabaseInstance *sqladmin.DatabaseInstance
}
