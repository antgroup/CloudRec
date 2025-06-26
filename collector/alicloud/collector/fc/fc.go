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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"fmt"
	fc20230330 "github.com/alibabacloud-go/fc-20230330/v4/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/cloudrec/alicloud/collector"
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
			ResourceId:   "$.ResourceId",
			ResourceName: "$.ResourceName",
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
	domain := describeCustomDomain(ctx, cli)

	function := describeFunction(ctx, cli)

	if len(domain) == 0 && len(function) == 0 {
		log.CtxLogger(ctx).Info("no fc resource found")
		return nil
	}

	res <- Detail{
		ResourceId:   fmt.Sprintf("fc_%s_%s", *cli.RegionId, services.CloudAccountId),
		ResourceName: fmt.Sprintf("fc_%s_%s", *cli.RegionId, services.CloudAccountId),
		Domain:       domain,
		Function:     function,
	}

	return nil
}

type Detail struct {
	ResourceId string

	ResourceName string

	// Custom domain name information
	Domain []*fc20230330.CustomDomain

	// Function Information
	Function []*fc20230330.Function
}

func describeCustomDomain(ctx context.Context, cli *fc20230330.Client) []*fc20230330.CustomDomain {
	listCustomDomainsRequest := &fc20230330.ListCustomDomainsRequest{}
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)

	result, err := cli.ListCustomDomainsWithOptions(listCustomDomainsRequest, headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListCustomDomainsWithOptions error", zap.Error(err))
		return nil
	}

	return result.Body.CustomDomains
}

func describeFunction(ctx context.Context, cli *fc20230330.Client) []*fc20230330.Function {
	listFunctionsRequest := &fc20230330.ListFunctionsRequest{}
	headers := make(map[string]*string)

	result, err := cli.ListFunctionsWithOptions(listFunctionsRequest, headers, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListFunctionsWithOptions error", zap.Error(err))
		return nil
	}

	return result.Body.Functions
}
