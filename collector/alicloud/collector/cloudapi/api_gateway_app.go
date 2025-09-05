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
	cloudapi20160714 "github.com/alibabacloud-go/cloudapi-20160714/v5/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetAPIGatewayAppResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.APIGatewayApp,
		ResourceTypeName:   "API Gateway App",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/CloudAPI`,
		ResourceDetailFunc: GetAPIGatewayAppDetail,
		RowField: schema.RowField{
			ResourceId:   "$.App.AppId",
			ResourceName: "$.App.AppName",
		},
		Dimension: schema.Global,
	}
}

type APIGatewayAppDetail struct {
	App            *cloudapi20160714.DescribeAppsResponseBodyAppsAppItem
	AppSecurity    *cloudapi20160714.DescribeAppSecurityResponseBody
	AuthorizedAPIs []*cloudapi20160714.DescribeAuthorizedApisResponseBodyAuthorizedApisAuthorizedApi
}

func GetAPIGatewayAppDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CloudAPI

	describeAppsRequest := &cloudapi20160714.DescribeAppsRequest{}
	describeAppsRequest.PageSize = tea.Int32(100)
	describeAppsRequest.PageNumber = tea.Int32(1)

	for {
		response, err := cli.DescribeApps(describeAppsRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeAppsWithOptions error", zap.Error(err))
			return err
		}

		if response.Body.Apps == nil || len(response.Body.Apps.AppItem) == 0 {
			break
		}

		for _, app := range response.Body.Apps.AppItem {
			appSecurity := getAppSecurity(ctx, cli, app.AppId)
			authorizedAPIs := getAuthorizedAPIs(ctx, cli, app.AppId)

			d := APIGatewayAppDetail{
				App:            app,
				AppSecurity:    appSecurity,
				AuthorizedAPIs: authorizedAPIs,
			}

			res <- d
		}

		// Check if there are more pages
		totalCount := tea.Int32Value(response.Body.TotalCount)
		pageSize := tea.Int32Value(describeAppsRequest.PageSize)
		currentPage := tea.Int32Value(describeAppsRequest.PageNumber)

		if currentPage*pageSize >= totalCount {
			break
		}

		describeAppsRequest.PageNumber = tea.Int32(currentPage + 1)
	}

	return nil
}

func getAppSecurity(ctx context.Context, cli *cloudapi20160714.Client, appId *int64) *cloudapi20160714.DescribeAppSecurityResponseBody {
	describeAppSecurityRequest := &cloudapi20160714.DescribeAppSecurityRequest{AppId: appId}

	response, err := cli.DescribeAppSecurity(describeAppSecurityRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAppSecurityWithOptions error", zap.Error(err), zap.Int64("appId", *appId))
		return nil
	}

	return response.Body
}

func getAuthorizedAPIs(ctx context.Context, cli *cloudapi20160714.Client, appId *int64) (allAPIs []*cloudapi20160714.DescribeAuthorizedApisResponseBodyAuthorizedApisAuthorizedApi) {
	describeAuthorizedApisRequest := &cloudapi20160714.DescribeAuthorizedApisRequest{}
	describeAuthorizedApisRequest.AppId = appId
	describeAuthorizedApisRequest.PageSize = tea.Int32(100)

	pageNumber := int32(1)

	for {
		describeAuthorizedApisRequest.PageNumber = tea.Int32(pageNumber)

		response, err := cli.DescribeAuthorizedApis(describeAuthorizedApisRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeAuthorizedApisWithOptions error", zap.Error(err), zap.Int64("appId", *appId))
			return allAPIs
		}

		if response.Body.AuthorizedApis == nil || len(response.Body.AuthorizedApis.AuthorizedApi) == 0 {
			break
		}

		allAPIs = append(allAPIs, response.Body.AuthorizedApis.AuthorizedApi...)

		// Check if there are more pages
		totalCount := tea.Int32Value(response.Body.TotalCount)
		pageSize := tea.Int32Value(describeAuthorizedApisRequest.PageSize)
		currentPage := pageNumber

		if currentPage*pageSize >= totalCount {
			break
		}

		pageNumber++
	}

	return allAPIs
}
