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

package eflo

import (
	"context"
	eflo_controller20221215 "github.com/alibabacloud-go/eflo-controller-20221215/v2/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetClusterResource returns Eflo Cluster resource definition
func GetClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EfloCluster,
		ResourceTypeName:   "EFLO Cluster",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://api.aliyun.com/product/eflo-controller",
		ResourceDetailFunc: GetClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.ClusterId",
			ResourceName: "$.Cluster.ClusterName",
		},
		Dimension: schema.Regional,
	}
}

// ClusterDetail aggregates resource details
type ClusterDetail struct {
	Cluster *eflo_controller20221215.ListClustersResponseBodyClusters
}

// GetClusterDetail gets Eflo Cluster details
func GetClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EfloController

	resources, err := listClusters(client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list nodes", zap.Error(err))
		return err
	}

	for _, cluster := range resources {
		res <- ClusterDetail{
			Cluster: cluster,
		}
	}

	return nil
}

// listClusters gets a list of Eflo Cluster
func listClusters(c *eflo_controller20221215.Client) ([]*eflo_controller20221215.ListClustersResponseBodyClusters, error) {
	var resources []*eflo_controller20221215.ListClustersResponseBodyClusters

	for {
		listClustersRequest := &eflo_controller20221215.ListClustersRequest{}

		resp, err := c.ListClusters(listClustersRequest)
		if err != nil {
			return nil, err
		}

		if resp.Body.Clusters != nil && len(resp.Body.Clusters) > 0 {
			resources = append(resources, resp.Body.Clusters...)
		}

		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		listClustersRequest.NextToken = resp.Body.NextToken
	}

	return resources, nil
}
