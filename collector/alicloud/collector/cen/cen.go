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

package cen

import (
	"context"
	"fmt"
	cbn20170912 "github.com/alibabacloud-go/cbn-20170912/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetCENResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CEN,
		ResourceTypeName:   "CEN",
		ResourceGroupType:  constant.NET,
		Desc:               "https://api.aliyun.com/product/Cbn",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cen.CenId",
			ResourceName: "$.Cen.Name",
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
			"cn-heyuan",
			"cn-guangzhou",
			"ap-southeast-6",
			"ap-southeast-3",
			"ap-northeast-1",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"na-south-1",
			"eu-west-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CEN

	describeCensRequest := &cbn20170912.DescribeCensRequest{}
	runtime := &util.RuntimeOptions{}

	Cens, err := cli.DescribeCensWithOptions(describeCensRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeCensWithOptions error", zap.Error(err))
		return err
	}

	if len(Cens.Body.Cens.Cen) == 0 {
		return nil
	}

	for _, cen := range Cens.Body.Cens.Cen {
		res <- Detail{
			Cen:            cen,
			TransitRouter:  describeTransitRouters(ctx, cli, cen.CenId),
			Flowlog:        describeFlowlogs(ctx, cli, cen.CenId),
			VbrHealthCheck: describeCenVbrHealthCheck(ctx, cli, cen.CenId),
		}

	}
	return nil
}

type Detail struct {
	// cen Instance Information
	Cen *cbn20170912.DescribeCensResponseBodyCensCen

	// Forwarding router instance information
	TransitRouter []*cbn20170912.ListTransitRoutersResponseBodyTransitRouters

	// Flow log information
	Flowlog []*cbn20170912.DescribeFlowlogsResponseBodyFlowLogsFlowLog

	// VBR Health Check Status
	VbrHealthCheck [][]*cbn20170912.DescribeCenVbrHealthCheckResponseBodyVbrHealthChecksVbrHealthCheck
}

// Query forwarding router information
func describeTransitRouters(ctx context.Context, cli *cbn20170912.Client, cenId *string) []*cbn20170912.ListTransitRoutersResponseBodyTransitRouters {
	listTransitRoutersRequest := &cbn20170912.ListTransitRoutersRequest{
		CenId: cenId,
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListTransitRoutersWithOptions(listTransitRoutersRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListTransitRoutersWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.TransitRouters
}

// Check whether the flow log is enabled
func describeFlowlogs(ctx context.Context, cli *cbn20170912.Client, cenId *string) []*cbn20170912.DescribeFlowlogsResponseBodyFlowLogsFlowLog {
	describeFlowlogsRequest := &cbn20170912.DescribeFlowlogsRequest{}
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeFlowlogsWithOptions(describeFlowlogsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeFlowlogsWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.FlowLogs.FlowLog
}

// Check whether VBR health check is enabled
func describeCenVbrHealthCheck(ctx context.Context, cli *cbn20170912.Client, cenId *string) [][]*cbn20170912.DescribeCenVbrHealthCheckResponseBodyVbrHealthChecksVbrHealthCheck {
	// Check whether VBR exists
	listTransitRouterVbrAttachmentsRequest := &cbn20170912.ListTransitRouterVbrAttachmentsRequest{
		CenId: cenId,
	}

	result, err := cli.ListTransitRouterVbrAttachmentsWithOptions(listTransitRouterVbrAttachmentsRequest, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListTransitRouterVbrAttachmentsWithOptions error", zap.Error(err))
		return nil
	}

	if len(result.Body.TransitRouterAttachments) == 0 {
		return nil
	}

	// Query VBR health check information
	var vbrHealthCheckList [][]*cbn20170912.DescribeCenVbrHealthCheckResponseBodyVbrHealthChecksVbrHealthCheck
	for _, vbr := range result.Body.TransitRouterAttachments {
		describeCenVbrHealthCheckRequest := &cbn20170912.DescribeCenVbrHealthCheckRequest{
			VbrInstanceRegionId: tea.String(*vbr.VbrRegionId),
			CenId:               tea.String(*vbr.CenId),
		}

		healthCheckResult, err := cli.DescribeCenVbrHealthCheckWithOptions(describeCenVbrHealthCheckRequest, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeCenVbrHealthCheckWithOptions error", zap.Error(err))
			return nil
		}
		fmt.Println(healthCheckResult.Body.VbrHealthChecks.VbrHealthCheck)
		vbrHealthCheckList = append(vbrHealthCheckList, healthCheckResult.Body.VbrHealthChecks.VbrHealthCheck)
	}

	return vbrHealthCheckList
}
