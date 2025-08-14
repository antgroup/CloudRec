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
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetImagesResource 返回ECS镜像资源定义
func GetImagesResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECSImage,
		ResourceTypeName:   "ECS Image",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://www.alibabacloud.com/help/product/ecs.html",
		ResourceDetailFunc: GetImagesDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Image.ImageId",
			ResourceName: "$.Image.ImageName",
		},
		Dimension: schema.Regional,
	}
}

// ImageDetail 聚合ECS镜像详细信息
type ImageDetail struct {
	Image ecs.Image
}

// GetImagesDetail 获取ECS镜像详细信息
func GetImagesDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECS

	images, err := listImages(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list ecs images", zap.Error(err))
		return err
	}

	for _, image := range images {
		res <- &ImageDetail{
			Image: image,
		}
	}
	
	return nil
}

// listImages 获取ECS镜像列表
func listImages(ctx context.Context, c *ecs.Client) ([]ecs.Image, error) {
	var images []ecs.Image

	req := ecs.CreateDescribeImagesRequest()
	req.PageSize = requests.NewInteger(constant.DefaultPageSize)
	req.PageNumber = requests.NewInteger(constant.DefaultPage)

	count := 0
	for {
		resp, err := c.DescribeImages(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeImages error", zap.Error(err))
			return nil, err
		}

		images = append(images, resp.Images.Image...)
		count += len(resp.Images.Image)

		if count >= resp.TotalCount || len(resp.Images.Image) < constant.DefaultPageSize {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return images, nil
}
