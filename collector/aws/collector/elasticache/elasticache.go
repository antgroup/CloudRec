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

package elasticache

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetElastiCacheClusterResource returns a ElastiCacheCluster Resource
func GetElastiCacheClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ElastiCache,
		ResourceTypeName:   "ElastiCache",
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeCacheClusters.html`,
		ResourceDetailFunc: GetCacheClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.CacheCluster.CacheClusterId",
			ResourceName: "$.CacheCluster.CacheClusterId",
		},
		Dimension: schema.Regional,
	}
}

type CacheClusterDetail struct {
	CacheCluster types.CacheCluster
}

func GetCacheClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ElastiCache

	cacheClusterDetails, err := describeCacheClusterDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeCacheClusterDetails error", zap.Error(err))
		return err
	}

	for _, cacheClusterDetail := range cacheClusterDetails {
		res <- cacheClusterDetail
	}
	return nil
}

func describeCacheClusterDetails(ctx context.Context, c *elasticache.Client) (cacheClusterDetails []CacheClusterDetail, err error) {
	cacheClusters, err := describeCacheClusters(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeCacheClusters error", zap.Error(err))
		return nil, err
	}
	for _, cacheCluster := range cacheClusters {
		cacheClusterDetails = append(cacheClusterDetails, CacheClusterDetail{
			CacheCluster: cacheCluster,
		})
	}

	return cacheClusterDetails, nil
}

func describeCacheClusters(ctx context.Context, c *elasticache.Client) (cacheClusters []types.CacheCluster, err error) {
	input := &elasticache.DescribeCacheClustersInput{}
	output, err := c.DescribeCacheClusters(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeCacheClusters error", zap.Error(err))
		return nil, err
	}
	cacheClusters = append(cacheClusters, output.CacheClusters...)
	for output.Marker != nil {
		input.Marker = output.Marker
		output, err = c.DescribeCacheClusters(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeCacheClusters error", zap.Error(err))
			return nil, err
		}
		cacheClusters = append(cacheClusters, output.CacheClusters...)
	}

	return cacheClusters, nil
}
