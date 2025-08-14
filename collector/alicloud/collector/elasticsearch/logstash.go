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

package elasticsearch

import (
	"context"
	"github.com/alibabacloud-go/elasticsearch-20170613/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetLogstashResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ElasticsearchLogstash,
		ResourceTypeName:   collector.ElasticsearchLogstash,
		ResourceGroupType:  constant.LOG,
		Desc:               `https://api.aliyun.com/product/elasticsearch`,
		ResourceDetailFunc: GetLogstashDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.instanceId",
			ResourceName: "$.Instance.description",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"cn-guangzhou",
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
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
		},
		Dimension: schema.Regional,
	}
}

type LogstashDetail struct {
	Instance *client.ListLogstashResponseBodyResult
}

func GetLogstashDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Elasticsearch

	size := 50
	page := 1
	for {
		listLogstashRequest := &client.ListLogstashRequest{
			Page: tea.Int32(int32(page)),
			Size: tea.Int32(int32(size)),
		}
		resp, err := cli.ListLogstash(listLogstashRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListLogstashWithOptions error", zap.Error(err))
			return err
		}
		for _, i := range resp.Body.Result {
			d := &LogstashDetail{
				Instance: i,
			}
			res <- d
		}

		if len(resp.Body.Result) < size {
			break
		}

		page++
	}

	return nil
}
