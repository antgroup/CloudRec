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
	"sync"
)

const (
	maxWorkers = 10
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

	var wg sync.WaitGroup
	jobs := make(chan types.Cluster, len(clusters))

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cluster := range jobs {
				detail := describeClusterDetail(ctx, client, cluster)
				res <- detail
			}
		}()
	}

	for _, cluster := range clusters {
		jobs <- cluster
	}
	close(jobs)

	wg.Wait()

	return nil
}

func describeClusterDetail(ctx context.Context, client *ecs.Client, cluster types.Cluster) interface{} {
	var wg sync.WaitGroup
	var services []types.Service
	var tasks []types.Task

	wg.Add(2)

	go func() {
		defer wg.Done()
		services, _ = listServices(ctx, client, *cluster.ClusterArn)
	}()

	go func() {
		defer wg.Done()
		tasks, _ = listTasks(ctx, client, *cluster.ClusterArn)
	}()

	wg.Wait()

	return &ClusterDetail{
		Cluster:  cluster,
		Services: services,
		Tasks:    tasks,
	}
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
func listServices(ctx context.Context, c *ecs.Client, clusterArn string) ([]types.Service, error) {
	var services []types.Service
	paginator := ecs.NewListServicesPaginator(c, &ecs.ListServicesInput{Cluster: &clusterArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if len(page.ServiceArns) > 0 {
			describedServices, err := c.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: &clusterArn, Services: page.ServiceArns, Include: []types.ServiceField{types.ServiceFieldTags}})
			if err != nil {
				return nil, err
			}
			services = append(services, describedServices.Services...)
		}
	}
	return services, nil
}

// listTasks retrieves all ECS task ARNs in a cluster.
func listTasks(ctx context.Context, c *ecs.Client, clusterArn string) ([]types.Task, error) {
	var tasks []types.Task
	paginator := ecs.NewListTasksPaginator(c, &ecs.ListTasksInput{Cluster: &clusterArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if len(page.TaskArns) > 0 {
			describedTasks, err := c.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: &clusterArn, Tasks: page.TaskArns, Include: []types.TaskField{types.TaskFieldTags}})
			if err != nil {
				return nil, err
			}
			tasks = append(tasks, describedTasks.Tasks...)
		}
	}
	return tasks, nil
}
