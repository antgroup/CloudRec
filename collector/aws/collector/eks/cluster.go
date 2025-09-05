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

package eks

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetClusterResource returns a Cluster Resource
func GetClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EKSCluster,
		ResourceTypeName:   "EKS Cluster",
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html`,
		ResourceDetailFunc: GetClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.Arn",
			ResourceName: "$.Cluster.Name",
		},
		Dimension: schema.Regional,
	}
}

// ClusterDetail aggregates all information for a single EKS cluster.
type ClusterDetail struct {
	Cluster *types.Cluster
}

// GetClusterDetail fetches the details for all EKS clusters in a region.
func GetClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EKS

	clusterNames, err := listClusters(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list eks clusters", zap.Error(err))
		return err
	}

	for _, name := range clusterNames {
		detail, err := describeCluster(ctx, client, name)
		if err != nil {
			log.CtxLogger(ctx).Error("failed to describe eks cluster", zap.Error(err))
			continue
		}
		res <- detail
	}

	return nil
}

// listClusters retrieves all EKS cluster names in a region.
func listClusters(ctx context.Context, c *eks.Client) ([]string, error) {
	var clusterNames []string
	paginator := eks.NewListClustersPaginator(c, &eks.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		clusterNames = append(clusterNames, page.Clusters...)
	}
	return clusterNames, nil
}

// describeCluster retrieves the details for a single cluster.
func describeCluster(ctx context.Context, c *eks.Client, name string) (*ClusterDetail, error) {
	output, err := c.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
	if err != nil {
		return nil, err
	}
	return &ClusterDetail{Cluster: output.Cluster}, nil
}
