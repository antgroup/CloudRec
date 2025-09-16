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

package datahub

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/yundun-ds"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetDataHubProjectResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DataHubProject,
		ResourceTypeName:   collector.DataHubProject,
		ResourceGroupType:  constant.BIGDATA,
		Desc:               `https://api.aliyun.com/product/Yundun-ds`,
		ResourceDetailFunc: GetProjectDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Project.Id",
			ResourceName: "$.Project.Name",
		},
		Dimension: schema.Global,
	}
}

type ProjectDetail struct {
	Project       yundun_ds.Project
	Topics        []yundun_ds.Topic
	Subscriptions []yundun_ds.Subscription
	Connectors    []yundun_ds.Connector
}

func GetProjectDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).YundunDs

	request := yundun_ds.CreateDescribeDataHubProjectsRequest()
	request.Scheme = "https"
	request.PageSize = requests.NewInteger(100)
	request.CurrentPage = requests.NewInteger(1)

	for {
		response, err := cli.DescribeDataHubProjects(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDataHubProjects error", zap.Error(err))
			return err
		}

		for _, project := range response.Items {
			topics := listTopicsForProject(ctx, cli, project.Id)
			subscriptions := listSubscriptionsForProject(ctx, cli, project.Id)
			connectors := listConnectorsForProject(ctx, cli, project.Id)

			d := ProjectDetail{
				Project:       project,
				Topics:        topics,
				Subscriptions: subscriptions,
				Connectors:    connectors,
			}
			res <- d
		}

		if response.CurrentPage*response.PageSize >= response.TotalCount {
			break
		}

		currentPage := response.CurrentPage + 1
		request.CurrentPage = requests.NewInteger(currentPage)
	}
	return nil
}

func listTopicsForProject(ctx context.Context, cli *yundun_ds.Client, projectId int64) (topics []yundun_ds.Topic) {
	request := yundun_ds.CreateDescribeDataHubTopicsRequest()
	request.Scheme = "https"
	request.ProjectId = requests.NewInteger(int(projectId))
	request.PageSize = requests.NewInteger(100)
	request.CurrentPage = requests.NewInteger(1)

	for {
		response, err := cli.DescribeDataHubTopics(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDataHubTopics error", zap.Error(err))
			return nil
		}

		topics = append(topics, response.Items...)

		if len(topics) >= response.TotalCount {
			break
		}

		request.CurrentPage = requests.NewInteger(response.CurrentPage + 1)
	}

	return topics
}

func listSubscriptionsForProject(ctx context.Context, cli *yundun_ds.Client, projectId int64) (subscriptions []yundun_ds.Subscription) {
	request := yundun_ds.CreateDescribeDataHubSubscriptionsRequest()
	request.Scheme = "https"
	request.ProjectId = requests.NewInteger(int(projectId))
	request.PageSize = requests.NewInteger(100)
	request.CurrentPage = requests.NewInteger(1)

	for {
		response, err := cli.DescribeDataHubSubscriptions(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDataHubSubscriptions error", zap.Error(err))
			return nil
		}

		subscriptions = append(subscriptions, response.Items...)

		if len(subscriptions) >= response.TotalCount {
			break
		}

		request.CurrentPage = requests.NewInteger(response.CurrentPage + 1)
	}

	return subscriptions
}

func listConnectorsForProject(ctx context.Context, cli *yundun_ds.Client, projectId int64) (connectors []yundun_ds.Connector) {
	request := yundun_ds.CreateDescribeDataHubConnectorsRequest()
	request.Scheme = "https"
	request.ProjectId = requests.NewInteger(int(projectId))
	request.PageSize = requests.NewInteger(100)
	request.CurrentPage = requests.NewInteger(1)

	for {
		response, err := cli.DescribeDataHubConnectors(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDataHubConnectors error", zap.Error(err))
			return nil
		}

		connectors = append(connectors, response.Items...)

		if len(connectors) >= response.TotalCount {
			break
		}

		request.CurrentPage = requests.NewInteger(response.CurrentPage + 1)
	}

	return connectors
}
