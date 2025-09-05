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

package ecp

import (
	"context"
	aic20230930 "github.com/alibabacloud-go/eds-aic-20230930/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ECPInstance,
		ResourceTypeName:   collector.ECPInstance,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://api.aliyun.com/product/ecp`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.AndroidInstanceId",
			ResourceName: "$.Instance.AndroidInstanceName",
		},
		Regions: []string{
			"cn-hangzhou",
			"cn-shanghai",
			"cn-beijing",
			"cn-shenzhen",
			"cn-qingdao",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-chengdu",
			"cn-hongkong",
			"ap-southeast-1",
			"ap-southeast-3",
			"ap-southeast-5",
			"ap-northeast-1",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
		},
		Dimension: schema.Regional,
	}
}

type InstanceDetail struct {
	Instance *aic20230930.DescribeAndroidInstancesResponseBodyInstanceModel
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ECP

	maxResults := 50
	nextToken := ""

	for {
		describeAndroidInstancesRequest := &aic20230930.DescribeAndroidInstancesRequest{
			MaxResults: tea.Int32(int32(maxResults)),
			NextToken:  tea.String(nextToken),
		}
		resp, err := cli.DescribeAndroidInstances(describeAndroidInstancesRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeAndroidInstances error", zap.Error(err))
			return err
		}

		if resp.Body.InstanceModel == nil || len(resp.Body.InstanceModel) == 0 {
			break
		}

		for _, instance := range resp.Body.InstanceModel {
			inst := instance
			d := &InstanceDetail{
				Instance: inst,
			}
			res <- d
		}

		if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
			break
		}
		nextToken = *resp.Body.NextToken
	}

	return nil
}
