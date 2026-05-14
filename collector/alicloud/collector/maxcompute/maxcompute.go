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

package maxcompute

import (
	"context"
	"os"
	"strings"

	maxcompute20220104 "github.com/alibabacloud-go/maxcompute-20220104/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"

	"github.com/alibabacloud-go/maxcompute-20220104/client"
)

const envMaxComputeTenantID = "ALIBABA_CLOUD_MAXCOMPUTE_TENANT_ID"

type Detail struct {
	Project                    *maxcompute20220104.ListProjectsResponseBodyDataProjects
	GetProjectResponseBodyData *maxcompute20220104.GetProjectResponseBodyData
}

func GetMaxComputeResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MAX_COMPUTE,
		ResourceTypeName:   "MaxCompute",
		ResourceGroupType:  constant.BIGDATA,
		Desc:               `https://api.aliyun.com/product/MaxCompute`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Project.name",
			ResourceName: "$.Project.comment",
		},
		Regions: []string{
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"ap-southeast-3",
			"ap-northeast-1",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
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
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Maxcompute
	req := &client.ListProjectsRequest{}
	req.MaxItem = tea.Int32(50)
	if region := maxComputeRegion(ctx); region != "" {
		req.Region = tea.String(region)
	}
	if tenantID := maxComputeTenantID(ctx); tenantID != "" {
		req.TenantId = tea.String(tenantID)
	}
	headers := make(map[string]*string)

	for {
		resp, err := cli.ListProjectsWithOptions(req, headers, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListProjectsWithOptions error", zap.Error(err))
			return err
		}
		if resp == nil || resp.Body == nil || resp.Body.Data == nil || len(resp.Body.Data.Projects) == 0 {
			return nil
		}

		// get security check info
		for _, p := range resp.Body.Data.Projects {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case res <- Detail{
				Project:                    p,
				GetProjectResponseBodyData: getProject(ctx, cli, p.Name),
			}:
			}
		}

		nextToken := tea.StringValue(resp.Body.Data.NextToken)
		if nextToken == "" {
			break
		}
		req.Marker = tea.String(nextToken)
	}

	return nil
}

func maxComputeTenantID(ctx context.Context) string {
	return firstNonEmptyString(
		collector.ContextConfigValue(ctx, "maxcompute_tenant_id", "maxcomputeTenantId", "maxcompute_tenant", "maxcomputeTenant"),
		os.Getenv(envMaxComputeTenantID),
	)
}

func maxComputeRegion(ctx context.Context) string {
	if regionID, ok := ctx.Value(constant.RegionId).(string); ok {
		regionID = strings.TrimSpace(regionID)
		if regionID != "" && regionID != "global" {
			return regionID
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// Get project details
func getProject(ctx context.Context, cli *maxcompute20220104.Client, name *string) (Data *maxcompute20220104.GetProjectResponseBodyData) {
	headers := make(map[string]*string)
	confReq := &client.GetProjectRequest{}
	r, err := cli.GetProjectWithOptions(name, confReq, headers, collector.RuntimeObject)

	if err != nil {
		log.CtxLogger(ctx).Warn("GetProjectWithOptions error", zap.Error(err))
		return
	}
	if r == nil || r.Body == nil || r.Body.Data == nil {
		return
	}

	return r.Body.Data
}
