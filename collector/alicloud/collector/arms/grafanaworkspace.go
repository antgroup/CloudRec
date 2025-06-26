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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	arms20190808 "github.com/alibabacloud-go/arms-20190808/v8/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetGrafanaWorkspaceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.GrafanaWorkspace,
		ResourceTypeName:   "GrafanaWorkspace",
		ResourceGroupType:  constant.CONFIG,
		Desc:               "https://api.aliyun.com/product/ARMS",
		ResourceDetailFunc: GetGrafanaWorkspaceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.GrafanaWorkspace.grafanaWorkspaceId",
			ResourceName: "$.GrafanaWorkspace.grafanaWorkspaceName",
			Address:      "$.GrafanaWorkspace.grafanaWorkspaceIp",
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

type GrafanaWorkspaceDetail struct {
	// GrafanaWorkspace information
	GrafanaWorkspace *arms20190808.GrafanaWorkspace
}

func GetGrafanaWorkspaceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.ARMS

	grafanaWorkspaces := describeGrafanaWorkspaces(ctx, cli, *cli.RegionId)
	for _, workspace := range grafanaWorkspaces {
		res <- GrafanaWorkspaceDetail{
			GrafanaWorkspace: workspace,
		}
	}

	return nil
}

// Get Grafana workspace information
func describeGrafanaWorkspaces(ctx context.Context, cli *arms20190808.Client, regionId string) []*arms20190808.GrafanaWorkspace {
	// Get a list of workspaces
	listGrafanaWorkspaceRequest := &arms20190808.ListGrafanaWorkspaceRequest{
		RegionId: tea.String(regionId),
	}
	runtime := &util.RuntimeOptions{}

	workspaces, err := cli.ListGrafanaWorkspaceWithOptions(listGrafanaWorkspaceRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListGrafanaWorkspaceWithOptions error", zap.Error(err))
		return nil
	}

	// If no data is queried, return
	if len(workspaces.Body.Data) == 0 {
		log.CtxLogger(ctx).Info("no data")
		return nil
	}

	// Query workspace details
	var result []*arms20190808.GrafanaWorkspace
	for _, workspace := range workspaces.Body.Data {
		getGrafanaWorkspaceRequest := &arms20190808.GetGrafanaWorkspaceRequest{
			RegionId:           tea.String(regionId),
			GrafanaWorkspaceId: tea.String(*workspace.GrafanaWorkspaceId),
		}
		runtime = &util.RuntimeOptions{}

		detail, err := cli.GetGrafanaWorkspaceWithOptions(getGrafanaWorkspaceRequest, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetGrafanaWorkspaceWithOptions error", zap.Error(err))
			return nil
		}

		result = append(result, detail.Body.Data)
	}
	return result
}
