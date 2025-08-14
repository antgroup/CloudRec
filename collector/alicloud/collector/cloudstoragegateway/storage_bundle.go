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

package cloudstoragegateway

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sgw"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetCloudStorageGatewayStorageBundleResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudStorageGatewayStorageBundle,
		ResourceTypeName:   "CloudStorageGateway Storage Bundle",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/sgw`,
		ResourceDetailFunc: GetCloudStorageGatewayStorageBundleDetail,
		RowField: schema.RowField{
			ResourceId:   "$.StorageBundle.StorageBundleId",
			ResourceName: "$.StorageBundle.Name",
		},
		Dimension: schema.Global,
	}
}

type CloudStorageGatewayStorageBundleDetail struct {
	StorageBundle sgw.StorageBundle
}

func GetCloudStorageGatewayStorageBundleDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).SGW

	describeStorageBundlesRequest := sgw.CreateDescribeStorageBundlesRequest()
	describeStorageBundlesRequest.Scheme = "https"
	describeStorageBundlesRequest.PageSize = requests.NewInteger(100)
	describeStorageBundlesRequest.PageNumber = requests.NewInteger(1)

	for {
		response, err := cli.DescribeStorageBundles(describeStorageBundlesRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeStorageBundles error", zap.Error(err))
			return err
		}

		if len(response.StorageBundles.StorageBundle) == 0 {
			break
		}

		for _, storageBundle := range response.StorageBundles.StorageBundle {
			d := CloudStorageGatewayStorageBundleDetail{
				StorageBundle: storageBundle,
			}

			res <- d
		}

		// Check if there are more pages
		totalCount := response.TotalCount
		pageSize := describeStorageBundlesRequest.PageSize
		pageNumber := describeStorageBundlesRequest.PageNumber

		pageNum, _ := pageNumber.GetValue()
		pageSizeNum, _ := pageSize.GetValue()
		totalNum := totalCount

		if pageNum*pageSizeNum >= totalNum {
			break
		}

		describeStorageBundlesRequest.PageNumber = requests.NewInteger(pageNum + 1)
	}

	return nil
}
