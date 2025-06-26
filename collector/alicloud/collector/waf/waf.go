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

package waf

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	waf_openapi20211001 "github.com/alibabacloud-go/waf-openapi-20211001/v4/client"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetWAFResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.WAF,
		ResourceTypeName:   collector.WAF,
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/waf-openapi`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId: "$.Instance.InstanceId",
		},
		Dimension: schema.Global,
		Regions:   []string{"cn-hangzhou", "ap-southeast-1"},
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.WAF
	describeInstanceRequest := &waf_openapi20211001.DescribeInstanceRequest{
		RegionId: services.Config.RegionId,
	}
	runtime := &util.RuntimeOptions{}
	resp, err := cli.DescribeInstanceWithOptions(describeInstanceRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstanceWithOptions error", zap.Error(err))
		return err
	}
	if resp.Body.Details == nil {
		return nil
	}

	d := &Detail{
		Instance:  resp.Body,
		Resources: describeDefenseResources(ctx, cli, resp.Body.InstanceId, services.Config.RegionId),
	}

	res <- d
	return nil
}

type Detail struct {
	Instance *waf_openapi20211001.DescribeInstanceResponseBody

	Resources []*ResourceDetail
}

type ResourceDetail struct {
	Resource *waf_openapi20211001.DescribeDefenseResourcesResponseBodyResources

	LogStatus bool
}

// Get the details of the WAF instance under the current Alibaba Cloud account
func describeDefenseResources(ctx context.Context, cli *waf_openapi20211001.Client, instanceId *string, regionId *string) (res []*ResourceDetail) {
	request := &waf_openapi20211001.DescribeDefenseResourcesRequest{
		RegionId: regionId,
	}

	request.PageSize = tea.Int32(10)
	request.PageNumber = tea.Int32(1)

	request.InstanceId = instanceId

	count := int64(0)
	for {
		runtime := &util.RuntimeOptions{}
		resp, err := cli.DescribeDefenseResourcesWithOptions(request, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDefenseResourcesWithOptions error", zap.Error(err))
			return
		}

		for _, r := range resp.Body.Resources {
			rd := &ResourceDetail{
				Resource:  r,
				LogStatus: describeResourceLogStatus(ctx, cli, instanceId, r.Resource, regionId),
			}
			res = append(res, rd)
		}

		count += int64(len(resp.Body.Resources))
		if count >= tea.Int64Value(resp.Body.TotalCount) {
			break
		}

		request.PageNumber = tea.Int32(tea.Int32Value(request.PageNumber) + int32(1))

	}

	return res
}

// Query the log status of the protection object
func describeResourceLogStatus(ctx context.Context, cli *waf_openapi20211001.Client, instanceId *string, resource *string, regionId *string) (status bool) {
	request := &waf_openapi20211001.DescribeResourceLogStatusRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
		// only one resource input
		Resources: resource,
	}

	runtime := &util.RuntimeOptions{}
	response, err := cli.DescribeResourceLogStatusWithOptions(request, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeResourceLogStatusWithOptions error", zap.Error(err))
		return
	}

	if response.Body == nil || len(response.Body.Result) == 0 {
		return
	}

	return tea.BoolValue(response.Body.Result[0].Status)

}
