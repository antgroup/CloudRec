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

package sls

import (
	"context"
	"go.uber.org/zap"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"

	sls20201230 "github.com/alibabacloud-go/sls-20201230/v6/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
)

func GetSLSResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SLS,
		ResourceTypeName:   "SLS",
		ResourceGroupType:  constant.STORE,
		Desc:               `https://api.aliyun.com/product/Sls`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.LogProject.projectName",
			ResourceName: "$.LogProject.projectName",
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
	cli := service.(*collector.Services).SLS
	listProjectRequest := &sls20201230.ListProjectRequest{}
	listProjectRequest.Size = tea.Int32(500)
	listProjectRequest.Offset = tea.Int32(0)
	count := 0

	runtime := &util.RuntimeOptions{
		ConnectTimeout: tea.Int(10000),
		ReadTimeout:    tea.Int(10000),
	}
	for {
		headers := make(map[string]*string)
		projects, err := cli.ListProjectWithOptions(listProjectRequest, headers, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListProjectWithOptions error", zap.Error(err))
			return err
		}

		if len(projects.Body.Projects) == 0 {
			return nil
		}

		for _, project := range projects.Body.Projects {
			res <- Detail{
				RegionId:     cli.RegionId,
				LogProject:   describeProject(ctx, cli, *project.ProjectName),
				PolicyStatus: describeProjectPolicy(ctx, cli, *project.ProjectName),
				Alert:        describeAlert(ctx, cli, *project.ProjectName),
				LogStore:     describeLogStore(ctx, cli, *project.ProjectName),
			}
			count++
		}

		if count >= int(*projects.Body.Total) {
			break
		}
		listProjectRequest.Offset = tea.Int32(*listProjectRequest.Offset + 1)
	}

	return nil
}

type Detail struct {
	RegionId *string

	// project information
	LogProject *sls20201230.Project

	// project policy information
	PolicyStatus *sls20201230.GetProjectPolicyResponse

	// logstore information
	LogStore []*sls20201230.Logstore

	// Alarm settings
	Alert []*sls20201230.Alert
}

// Get project info
func describeProject(ctx context.Context, cli *sls20201230.Client, projectName string) *sls20201230.Project {
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)
	projectDetail, err := cli.GetProjectWithOptions(tea.String(projectName), headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetProjectWithOptions error", zap.Error(err))
		return nil
	}

	return projectDetail.Body
}

// Check whether the authorization policy is set
func describeProjectPolicy(ctx context.Context, cli *sls20201230.Client, projectName string) *sls20201230.GetProjectPolicyResponse {
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)
	result, err := cli.GetProjectPolicyWithOptions(tea.String(projectName), headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetProjectPolicyWithOptions error", zap.Error(err))
		return nil
	}

	return result
}

// Query Logstore Information
func describeLogStore(ctx context.Context, cli *sls20201230.Client, projectName string) []*sls20201230.Logstore {
	listLogStoresRequest := &sls20201230.ListLogStoresRequest{}
	listLogStoresRequest.Offset = tea.Int32(0)
	listLogStoresRequest.Size = tea.Int32(500)
	count := 0

	var result []*sls20201230.Logstore

	for {
		runtime := &util.RuntimeOptions{}
		headers := make(map[string]*string)

		logStores, err := cli.ListLogStoresWithOptions(tea.String(projectName), listLogStoresRequest, headers, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListLogStoresWithOptions error", zap.Error(err))
			return nil
		}

		for _, logStore := range logStores.Body.Logstores {
			runtime = &util.RuntimeOptions{}
			headers = make(map[string]*string)
			detail, err := cli.GetLogStoreWithOptions(tea.String(projectName), tea.String(*logStore), headers, runtime)
			if err != nil {
				log.CtxLogger(ctx).Warn("GetLogStoreWithOptions error", zap.Error(err))
				return nil
			}
			result = append(result, detail.Body)
			count++
		}

		if count >= int(*logStores.Body.Total) {
			break
		}
		listLogStoresRequest.Offset = tea.Int32(*listLogStoresRequest.Offset + 1)
	}

	return result
}

// Check whether an alarm is set
func describeAlert(ctx context.Context, cli *sls20201230.Client, projectName string) []*sls20201230.Alert {
	// Only pay attention to whether there are alarm rules and do not perform pagination queries
	listAlertsRequest := &sls20201230.ListAlertsRequest{
		Offset: tea.Int32(0),
		Size:   tea.Int32(10),
	}
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)

	result, err := cli.ListAlertsWithOptions(tea.String(projectName), listAlertsRequest, headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAlertsWithOptions error", zap.Error(err))
		return nil
	}

	return result.Body.Results
}
