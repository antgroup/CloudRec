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

package ecs

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetClusterResource returns a Cluster Resource
func GetClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECSCluster,
		ResourceTypeName:   "ECS Cluster",
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeClusters.html`,
		ResourceDetailFunc: GetClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.ClusterArn",
			ResourceName: "$.Cluster.ClusterName",
		},
		Dimension: schema.Regional,
	}
}

// ClusterDetail aggregates all information for a single ECS cluster.
type ClusterDetail struct {
	Cluster  types.Cluster
	Services []types.Service
	Tasks    []types.Task
}

// GetClusterDetail fetches the details for all ECS clusters in a region.
func GetClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECS

	clusterArns, err := listClusters(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list ecs clusters", zap.Error(err))
		return err
	}

	var clusters []types.Cluster
	// Describe clusters in batches of 100, which is the API limit.
	for i := 0; i < len(clusterArns); i += 100 {
		end := i + 100
		if end > len(clusterArns) {
			end = len(clusterArns)
		}
		batch := clusterArns[i:end]

		describedClusters, err := describeClusters(ctx, client, batch)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe ecs clusters", zap.Error(err))
			continue
		}
		clusters = append(clusters, describedClusters...)
	}

	for _, cluster := range clusters {

		services := listServices(ctx, client, *cluster.ClusterArn)

		tasks := listTasks(ctx, client, *cluster.ClusterArn)

		res <- &ClusterDetail{
			Cluster:  cluster,
			Services: services,
			Tasks:    tasks,
		}
	}

	return nil
}

// listClusters retrieves all ECS cluster ARNs in a region.
func listClusters(ctx context.Context, c *ecs.Client) ([]string, error) {
	var clusterArns []string
	paginator := ecs.NewListClustersPaginator(c, &ecs.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		clusterArns = append(clusterArns, page.ClusterArns...)
	}
	return clusterArns, nil
}

// describeClusters retrieves the details for a list of clusters.
func describeClusters(ctx context.Context, c *ecs.Client, clusterArns []string) ([]types.Cluster, error) {
	output, err := c.DescribeClusters(ctx, &ecs.DescribeClustersInput{Clusters: clusterArns, Include: []types.ClusterField{types.ClusterFieldTags, types.ClusterFieldSettings}})
	if err != nil {
		return nil, err
	}
	return output.Clusters, nil
}

// listServices retrieves all ECS service ARNs in a cluster.
func listServices(ctx context.Context, c *ecs.Client, clusterArn string) []types.Service {
	var services []types.Service
	paginator := ecs.NewListServicesPaginator(c, &ecs.ListServicesInput{Cluster: &clusterArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list ecs services", zap.Error(err))
			return nil
		}
		if len(page.ServiceArns) > 0 {
			describedServices, err := c.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: &clusterArn, Services: page.ServiceArns, Include: []types.ServiceField{types.ServiceFieldTags}})
			if err != nil {
				log.CtxLogger(ctx).Warn("failed to describe ecs services", zap.Error(err))
				return nil
			}
			services = append(services, describedServices.Services...)
		}
	}
	return services
}

// listTasks retrieves all ECS task ARNs in a cluster.
func listTasks(ctx context.Context, c *ecs.Client, clusterArn string) []types.Task {
	var tasks []types.Task
	paginator := ecs.NewListTasksPaginator(c, &ecs.ListTasksInput{Cluster: &clusterArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list ecs tasks", zap.Error(err))
			return nil
		}
		if len(page.TaskArns) > 0 {
			describedTasks, err := c.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: &clusterArn, Tasks: page.TaskArns, Include: []types.TaskField{types.TaskFieldTags}})
			if err != nil {
				log.CtxLogger(ctx).Warn("failed to describe ecs tasks", zap.Error(err))
				return nil
			}
			tasks = append(tasks, describedTasks.Tasks...)
		}
	}
	return tasks
}
