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

package cloudapi

import (
	"context"
	"sync"

	cloudapi20160714 "github.com/alibabacloud-go/cloudapi-20160714/v5/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const maxWorkers = 10

// GetAPIGatewayResource 返回API Gateway资源定义
func GetAPIGatewayResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.APIGateway,
		ResourceTypeName:   "API Gateway",
		ResourceGroupType:  constant.NET,
		Desc:               "https://api.aliyun.com/product/CloudAPI",
		ResourceDetailFunc: GetAPIGatewayDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ApiSummary.ApiId",
			ResourceName: "$.ApiSummary.ApiName",
		},
		Dimension: schema.Regional,
	}
}

// APIGatewayDetail 聚合API Gateway详细信息
type APIGatewayDetail struct {
	ApiSummary *cloudapi20160714.DescribeApisResponseBodyApiSummarysApiSummary
	ApiInfo    *cloudapi20160714.DescribeApiResponseBody
}

// GetAPIGatewayDetail 获取API Gateway详细信息
func GetAPIGatewayDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CloudAPI

	apis, err := listAPIs(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list apis", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan *cloudapi20160714.DescribeApisResponseBodyApiSummarysApiSummary, len(apis))

	// 启动工作协程
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for api := range tasks {
				detail := describeAPIDetail(ctx, client, api)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// 添加任务
	for _, api := range apis {
		tasks <- api
	}
	close(tasks)

	wg.Wait()
	return nil
}

// listAPIs 获取API列表
func listAPIs(ctx context.Context, c *cloudapi20160714.Client) ([]*cloudapi20160714.DescribeApisResponseBodyApiSummarysApiSummary, error) {
	var apis []*cloudapi20160714.DescribeApisResponseBodyApiSummarysApiSummary

	req := &cloudapi20160714.DescribeApisRequest{}
	req.PageSize = tea.Int32(constant.DefaultPageSize)
	req.PageNumber = tea.Int32(constant.DefaultPage)

	var count int32 = 0
	for {
		resp, err := c.DescribeApis(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeApis error", zap.Error(err))
			return nil, err
		}

		apis = append(apis, resp.Body.ApiSummarys.ApiSummary...)
		count += int32(len(resp.Body.ApiSummarys.ApiSummary))

		if count >= *resp.Body.TotalCount || len(resp.Body.ApiSummarys.ApiSummary) < constant.DefaultPageSize {
			break
		}
		req.PageNumber = tea.Int32(*resp.Body.PageNumber + 1)
	}

	return apis, nil
}

// describeAPIDetail 获取单个API详细信息
func describeAPIDetail(ctx context.Context, c *cloudapi20160714.Client, api *cloudapi20160714.DescribeApisResponseBodyApiSummarysApiSummary) *APIGatewayDetail {
	req := &cloudapi20160714.DescribeApiRequest{}
	req.ApiId = api.ApiId

	resp, err := c.DescribeApi(req)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeApi error", zap.Error(err), zap.String("apiId", *api.ApiId))
		return nil
	}

	return &APIGatewayDetail{
		ApiSummary: api,
		ApiInfo:    resp.Body,
	}
}
