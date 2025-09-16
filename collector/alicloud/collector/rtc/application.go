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

package rtc

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/rtc"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetRTCApplicationResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.RTCApplication,
		ResourceTypeName:   collector.RTCApplication,
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               `https://api.aliyun.com/product/RTC`,
		ResourceDetailFunc: GetRTCApplicationDetail,
		RowField: schema.RowField{
			ResourceId:   "$.App.AppId",
			ResourceName: "$.App.AppName",
		},
		Dimension: schema.Global,
	}
}

type ApplicationDetail struct {
	App    rtc.App
	AppKey string
}

func GetRTCApplicationDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RTC

	request := rtc.CreateDescribeAppsRequest()
	request.Scheme = "https"
	request.PageNum = requests.NewInteger(1)
	request.PageSize = requests.NewInteger(100)

	pageNum := 1
	for {
		response, err := cli.DescribeApps(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeApps error", zap.Error(err))
			return err
		}

		for _, app := range response.AppList.App {
			// Get additional details for each application
			appKey := getAppKey(ctx, cli, app.AppId)

			d := ApplicationDetail{
				App:    app,
				AppKey: appKey,
			}
			res <- d
		}

		// Check if there are more pages
		if pageNum >= response.TotalPage {
			break
		}
		pageNum++
		request.PageNum = requests.NewInteger(pageNum)
	}

	return nil
}

func getAppKey(ctx context.Context, cli *rtc.Client, appId string) string {
	request := rtc.CreateDescribeAppKeyRequest()
	request.Scheme = "https"
	request.AppId = appId

	response, err := cli.DescribeAppKey(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAppKey error", zap.Error(err))
		return ""
	}

	return response.AppKey
}
