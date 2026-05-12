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
	"sync"

	"go.uber.org/zap"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"

	sls20201230 "github.com/alibabacloud-go/sls-20201230/v6/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
)

const (
	slsPageSize            int32 = 500
	slsProjectConcurrency        = 4
	slsLogStoreConcurrency       = 4
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
	listProjectRequest.FetchQuota = tea.Bool(true)
	listProjectRequest.Size = tea.Int32(slsPageSize)
	listProjectRequest.Offset = tea.Int32(0)
	count := 0

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		headers := make(map[string]*string)
		projects, err := cli.ListProjectWithOptions(listProjectRequest, headers, slsRuntime())
		if err != nil {
			log.CtxLogger(ctx).Warn("ListProjectWithOptions error", zap.Error(err))
			return err
		}

		if len(projects.Body.Projects) == 0 {
			return nil
		}

		if err := collectProjects(ctx, cli, projects.Body.Projects, res); err != nil {
			return err
		}

		count += len(projects.Body.Projects)
		if count >= int(tea.Int64Value(projects.Body.Total)) {
			break
		}
		listProjectRequest.Offset = tea.Int32(tea.Int32Value(listProjectRequest.Offset) + int32(len(projects.Body.Projects)))
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

func slsRuntime() *util.RuntimeOptions {
	return &util.RuntimeOptions{
		Autoretry:      tea.Bool(true),
		MaxAttempts:    tea.Int(1),
		ConnectTimeout: tea.Int(10000),
		ReadTimeout:    tea.Int(10000),
	}
}

func collectProjects(ctx context.Context, cli *sls20201230.Client, projects []*sls20201230.Project, res chan<- any) error {
	sem := make(chan struct{}, slsProjectConcurrency)
	var wg sync.WaitGroup

	for _, project := range projects {
		if project == nil || tea.StringValue(project.ProjectName) == "" {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(project *sls20201230.Project) {
			defer wg.Done()
			defer func() { <-sem }()

			detail := collectProjectDetail(ctx, cli, project)
			select {
			case <-ctx.Done():
			case res <- detail:
			}
		}(project)
	}

	wg.Wait()
	return ctx.Err()
}

func collectProjectDetail(ctx context.Context, cli *sls20201230.Client, project *sls20201230.Project) Detail {
	projectName := tea.StringValue(project.ProjectName)
	logProject := project
	if project.Quota == nil {
		if detail := describeProject(ctx, cli, projectName); detail != nil {
			logProject = detail
		}
	}

	var (
		policyStatus *sls20201230.GetProjectPolicyResponse
		alerts       []*sls20201230.Alert
		logStores    []*sls20201230.Logstore
		wg           sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		policyStatus = describeProjectPolicy(ctx, cli, projectName)
	}()
	go func() {
		defer wg.Done()
		alerts = describeAlert(ctx, cli, projectName)
	}()
	go func() {
		defer wg.Done()
		logStores = describeLogStore(ctx, cli, projectName)
	}()
	wg.Wait()

	return Detail{
		RegionId:     cli.RegionId,
		LogProject:   logProject,
		PolicyStatus: policyStatus,
		Alert:        alerts,
		LogStore:     logStores,
	}
}

// Get project info
func describeProject(ctx context.Context, cli *sls20201230.Client, projectName string) *sls20201230.Project {
	headers := make(map[string]*string)
	projectDetail, err := cli.GetProjectWithOptions(tea.String(projectName), headers, slsRuntime())
	if err != nil {
		log.CtxLogger(ctx).Warn("GetProjectWithOptions error", zap.Error(err))
		return nil
	}

	return projectDetail.Body
}

// Check whether the authorization policy is set
func describeProjectPolicy(ctx context.Context, cli *sls20201230.Client, projectName string) *sls20201230.GetProjectPolicyResponse {
	headers := make(map[string]*string)
	result, err := cli.GetProjectPolicyWithOptions(tea.String(projectName), headers, slsRuntime())
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
	listLogStoresRequest.Size = tea.Int32(slsPageSize)
	count := 0

	var result []*sls20201230.Logstore

	for {
		if err := ctx.Err(); err != nil {
			return result
		}
		headers := make(map[string]*string)

		logStores, err := cli.ListLogStoresWithOptions(tea.String(projectName), listLogStoresRequest, headers, slsRuntime())
		if err != nil {
			log.CtxLogger(ctx).Warn("ListLogStoresWithOptions error", zap.Error(err))
			return nil
		}

		result = append(result, describeLogStoreDetails(ctx, cli, projectName, logStores.Body.Logstores)...)
		count += len(logStores.Body.Logstores)

		if count >= int(tea.Int32Value(logStores.Body.Total)) {
			break
		}
		listLogStoresRequest.Offset = tea.Int32(tea.Int32Value(listLogStoresRequest.Offset) + int32(len(logStores.Body.Logstores)))
	}

	return result
}

func describeLogStoreDetails(ctx context.Context, cli *sls20201230.Client, projectName string, logStores []*string) []*sls20201230.Logstore {
	details := make([]*sls20201230.Logstore, len(logStores))
	sem := make(chan struct{}, slsLogStoreConcurrency)
	var wg sync.WaitGroup

	for i, logStore := range logStores {
		name := tea.StringValue(logStore)
		if name == "" {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return compactLogStores(details)
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			headers := make(map[string]*string)
			detail, err := cli.GetLogStoreWithOptions(tea.String(projectName), tea.String(name), headers, slsRuntime())
			if err != nil {
				log.CtxLogger(ctx).Warn("GetLogStoreWithOptions error", zap.Error(err))
				return
			}
			details[i] = detail.Body
		}(i, name)
	}

	wg.Wait()
	return compactLogStores(details)
}

func compactLogStores(logStores []*sls20201230.Logstore) []*sls20201230.Logstore {
	result := make([]*sls20201230.Logstore, 0, len(logStores))
	for _, logStore := range logStores {
		if logStore != nil {
			result = append(result, logStore)
		}
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
	headers := make(map[string]*string)

	result, err := cli.ListAlertsWithOptions(tea.String(projectName), listAlertsRequest, headers, slsRuntime())
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAlertsWithOptions error", zap.Error(err))
		return nil
	}

	return result.Body.Results
}
