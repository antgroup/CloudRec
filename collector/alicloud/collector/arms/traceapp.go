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

package arms

import (
	"context"
	arms20190808 "github.com/alibabacloud-go/arms-20190808/v8/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetTraceAppResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.TraceApp,
		ResourceTypeName:   "TraceApp",
		ResourceGroupType:  constant.CONFIG,
		Desc:               "https://api.aliyun.com/product/ARMS",
		ResourceDetailFunc: GetTraceAppDetail,
		RowField: schema.RowField{
			ResourceId:   "$.App.AppId",
			ResourceName: "$.App.AppName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-nanjing",
			"cn-fuzhou",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-zhengzhou-jva",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func GetTraceAppDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.ARMS

	listTraceAppsRequest := &arms20190808.ListTraceAppsRequest{
		RegionId: tea.String(*cli.RegionId),
	}
	runtime := &util.RuntimeOptions{}
	apps, err := cli.ListTraceAppsWithOptions(listTraceAppsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("ListTraceAppsWithOptions error", zap.Error(err))
		return err
	}

	// If no data is queried, continue
	if len(apps.Body.TraceApps) == 0 {
		return nil
	}
	for _, app := range apps.Body.TraceApps {
		res <- TraceAppDetail{
			App: app,
		}
	}

	return nil
}

type TraceAppDetail struct {
	// Monitor application information
	App *arms20190808.ListTraceAppsResponseBodyTraceApps
}
