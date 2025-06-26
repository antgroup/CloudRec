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

package css

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/css/v1/model"
	"go.uber.org/zap"
)

func GetClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CSS,
		ResourceTypeName:   "CSS Cluster",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/CSS/sdk?version=v1&api=ListClustersDetails",
		ResourceDetailFunc: GetClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.id",
			ResourceName: "$.Cluster.name",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Cluster model.ClusterList
}

func GetClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CSS
	limit := int32(50)
	start := int32(1)
	request := &model.ListClustersDetailsRequest{
		Limit: &limit,
		Start: &start,
	}
	for {
		response, err := cli.ListClustersDetails(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListClustersDetails error", zap.Error(err))
			return err
		}

		for _, cluster := range *response.Clusters {
			res <- &Detail{
				Cluster: cluster,
			}
		}

		if len(*response.Clusters) < int(limit) {
			break
		}

		*request.Start = *request.Start + limit
	}
	return nil
}
