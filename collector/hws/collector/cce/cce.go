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

package cce

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	"go.uber.org/zap"
)

func GetClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CCE,
		ResourceTypeName:   "CCE Cluster",
		ResourceGroupType:  constant.CONTAINER,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/CCE/sdk?api=ListClusters",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Item.metadata.uid",
			ResourceName: "$.Item.metadata.name",
		},
		Dimension: schema.Regional,
	}
}

type ClusterDetail struct {
	Item model.Cluster
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CCE
	request := &model.ListClustersRequest{}
	response, err := cli.ListClusters(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListClusters error", zap.Error(err))
		return err
	}

	for _, item := range *response.Items {
		res <- &ClusterDetail{
			Item: item,
		}
	}
	return nil
}
