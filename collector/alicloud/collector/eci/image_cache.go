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

package eci

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eci"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetECIImageCacheResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECIImageCache,
		ResourceTypeName:   "ECI ImageCache",
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://api.aliyun.com/product/Eci`,
		ResourceDetailFunc: GetECIImageCacheDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ImageCache.ImageCacheId",
			ResourceName: "$.ImageCache.ImageCacheName",
		},
		Dimension: schema.Regional,
	}
}

type ECIImageCacheDetail struct {
	ImageCache eci.DescribeImageCachesImageCache0
}

// GetECIImageCacheDetail 实现容器镜像缓存的安全信息收集
func GetECIImageCacheDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ECI

	// 1. DescribeImageCaches - 获取镜像缓存列表，包含安全配置信息
	request := eci.CreateDescribeImageCachesRequest()
	request.Scheme = "https"

	response, err := cli.DescribeImageCaches(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeImageCaches error", zap.Error(err))
		return err
	}

	// 处理镜像缓存
	for _, ic := range response.ImageCaches {
		detail := ECIImageCacheDetail{
			ImageCache: ic,
		}

		res <- detail
	}

	return nil
}
