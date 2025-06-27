// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resourcecenter

import (
	"context"

	resourcecenter20221201 "github.com/alibabacloud-go/resourcecenter-20221201/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GeCloudCenterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ResourceCenter,
		ResourceTypeName:   collector.ResourceCenter,
		ResourceGroupType:  constant.GOVERNANCE,
		Desc:               `https://api.aliyun.com/product/ResourceCenter`,
		ResourceDetailFunc: GetDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ResourceId",
			ResourceName: "$.ResourceId",
		},
		Regions: []string{
			"cn-shanghai",
			"ap-southeast-1",
		},
		Dimension: schema.Regional,
	}
}

func GetDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ResourceCenter

	var sql = "SELECT resource_type,COUNT(*) AS cnt FROM resources GROUP BY  resource_type ORDER BY cnt DESC;"
	request := &resourcecenter20221201.ExecuteSQLQueryRequest{
		Expression: tea.String(sql),
		MaxResults: tea.Int32(100),
	}

	var columns []*resourcecenter20221201.ExecuteSQLQueryResponseBodyColumns
	var rows []interface{}
	for {
		resp, err := cli.ExecuteSQLQuery(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ExecuteSQLQuery error", zap.Error(err))
			return err
		}

		rows = append(rows, resp.Body.Rows...)

		if tea.StringValue(resp.Body.NextToken) == "" {
			columns = resp.Body.Columns
			break
		}

		request.NextToken = resp.Body.NextToken
	}

	if len(rows) == 0 {
		log.CtxLogger(ctx).Warn("Resource center query result is empty")
		return nil
	}

	res <- &Detail{
		Columns:    columns,
		Rows:       rows,
		ResourceId: log.GetCloudAccountId(ctx) + "-" + tea.StringValue(cli.RegionId),
	}

	return nil
}

type Detail struct {
	Columns    []*resourcecenter20221201.ExecuteSQLQueryResponseBodyColumns
	Rows       []interface{}
	ResourceId string
}
