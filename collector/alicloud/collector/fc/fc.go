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

package fc

import (
	"context"
	fc20230330 "github.com/alibabacloud-go/fc-20230330/v4/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetFCResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.FC,
		ResourceTypeName:   "FC",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://api.aliyun.com/product/FC",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Function.functionId",
			ResourceName: "$.Function.functionName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
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
			"me-central-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.FC

	function := describeFunction(ctx, cli)
	for _, f := range function {
		res <- Detail{
			Function: f,
			Triggers: describeTriggers(ctx, cli, f.FunctionName),
		}
	}

	return nil
}

type Detail struct {

	// Function Information
	Function *fc20230330.Function

	Triggers []*fc20230330.Trigger
}

func describeTriggers(ctx context.Context, cli *fc20230330.Client, name *string) (triggers []*fc20230330.Trigger) {
	request := &fc20230330.ListTriggersRequest{}
	resp, err := cli.ListTriggers(name, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListTriggersWithOptions error", zap.Error(err))
		return nil
	}
	triggers = append(triggers, resp.Body.Triggers...)

	for resp.Body.NextToken != nil {
		request.NextToken = resp.Body.NextToken
		resp, err = cli.ListTriggers(name, request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListTriggersWithOptions error", zap.Error(err))
			return nil
		}
		triggers = append(triggers, resp.Body.Triggers...)
	}

	return resp.Body.Triggers
}

func describeFunction(ctx context.Context, cli *fc20230330.Client) (functions []*fc20230330.Function) {
	listFunctionsRequest := &fc20230330.ListFunctionsRequest{}
	headers := make(map[string]*string)

	result, err := cli.ListFunctionsWithOptions(listFunctionsRequest, headers, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListFunctionsWithOptions error", zap.Error(err))
		return nil
	}
	functions = append(functions, result.Body.Functions...)

	if result.Body.NextToken != nil {
		listFunctionsRequest.NextToken = result.Body.NextToken
		result, err = cli.ListFunctionsWithOptions(listFunctionsRequest, headers, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListFunctionsWithOptions error", zap.Error(err))
			return nil
		}
		functions = append(functions, result.Body.Functions...)
	}

	return result.Body.Functions
}
