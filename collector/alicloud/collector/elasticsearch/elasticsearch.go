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
	elasticsearch20170613 "github.com/alibabacloud-go/elasticsearch-20170613/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Elasticsearch,
		ResourceTypeName:   collector.Elasticsearch,
		ResourceGroupType:  constant.BIGDATA,
		Desc:               `https://api.aliyun.com/product/elasticsearch`,
		ResourceDetailFunc: GetInstanceDetail,
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

type Detail struct {
	Instance        *elasticsearch20170613.ListInstanceResponseBodyResult
	InstanceDetail  *elasticsearch20170613.DescribeInstanceResponseBodyResult
	SnapshotSetting *elasticsearch20170613.DescribeSnapshotSettingResponseBodyResult
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Elasticsearch

	size := 50
	for {
		listInstanceRequest := &elasticsearch20170613.ListInstanceRequest{
			Page: tea.Int32(1),
			Size: tea.Int32(int32(size)),
		}
		headers := make(map[string]*string)
		resp, err := cli.ListInstanceWithOptions(listInstanceRequest, headers, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstanceWithOptions error", zap.Error(err))
			return err
		}
		for _, i := range resp.Body.Result {

			d := &Detail{
				Instance:        i,
				InstanceDetail:  describeInstance(ctx, cli, i.InstanceId),
				SnapshotSetting: describeSnapshotSetting(ctx, cli, i.InstanceId),
			}

			res <- d

		}

		count := len(resp.Body.Result)
		if count < size {
			break
		}

		*listInstanceRequest.Page = *listInstanceRequest.Page + 1
	}

	return nil
}

func describeInstance(ctx context.Context, cli *elasticsearch20170613.Client, instanceId *string) (Result *elasticsearch20170613.DescribeInstanceResponseBodyResult) {
	headers := make(map[string]*string)
	resp, err := cli.DescribeInstanceWithOptions(instanceId, headers, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstanceWithOptions error", zap.Error(err))
		return
	}
	return resp.Body.Result
}

func describeSnapshotSetting(ctx context.Context, cli *elasticsearch20170613.Client, instanceId *string) (Result *elasticsearch20170613.DescribeSnapshotSettingResponseBodyResult) {
	headers := make(map[string]*string)
	resp, err := cli.DescribeSnapshotSettingWithOptions(instanceId, headers, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeSnapshotSettingWithOptions error", zap.Error(err))
		return
	}

	return resp.Body.Result
}
