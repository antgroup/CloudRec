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

package opensearch

import (
	"context"
	opensearch20171225 "github.com/alibabacloud-go/opensearch-20171225/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetAppGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.OpenSearchAppGroup,
		ResourceTypeName:   collector.OpenSearchAppGroup,
		ResourceGroupType:  constant.BIGDATA,
		Desc:               `https://api.aliyun.com/product/OpenSearch`,
		ResourceDetailFunc: GetAppGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.AppGroup.Id",
			ResourceName: "$.AppGroup.Name",
		},
		Dimension: schema.Regional,
		Regions: []string{
			"cn-qingdao",
			"cn-hongkong",
			"ap-southeast-1",
			"cn-shenzhen",
			"cn-zhangjiakou",
			"cn-beijing",
			"cn-shanghai",
			"cn-hangzhou",
			"us-east-1",
			"eu-central-1",
		},
	}
}

type AppGroupDetail struct {
	AppGroup *opensearch20171225.ListAppGroupsResponseBodyResult
}

func GetAppGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).OpenSearch

	appGroups, err := listAppGroups(ctx, cli)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAppGroups error", zap.Error(err))
		return err
	}

	for _, appGroup := range appGroups {
		appGroupDetail := AppGroupDetail{
			AppGroup: appGroup,
		}
		res <- appGroupDetail
	}

	return nil
}

func listAppGroups(ctx context.Context, cli *opensearch20171225.Client) (appGroups []*opensearch20171225.ListAppGroupsResponseBodyResult, err error) {
	request := &opensearch20171225.ListAppGroupsRequest{
		PageNumber: tea.Int32(1),
	}

	for {
		response, err := cli.ListAppGroups(request)
		if err != nil {
			return nil, err
		}
		appGroups = append(appGroups, response.Body.Result...)

		if int32(len(appGroups)) >= *response.Body.TotalCount {
			break
		}
		request.PageNumber = tea.Int32(*request.PageNumber + 1)
	}

	return appGroups, nil
}
