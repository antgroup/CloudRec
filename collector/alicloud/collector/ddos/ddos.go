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

package ddos

import (
	"context"
	ddoscoo20200101 "github.com/alibabacloud-go/ddoscoo-20200101/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"strconv"
)

func GetDDoSBGPResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DdosCoo,
		ResourceTypeName:   "DDoS高防",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://next.api.aliyun.com/product/ddosbgp`,
		ResourceDetailFunc: GetDDoSBGPDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.Remark",
			Address:      "$.Instance.Ip",
		},
		Dimension: schema.Regional,
		Regions:   []string{"cn-hangzhou", "ap-southeast-1"},
	}
}

func GetDDoSBGPDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.DDoS

	var page = 1
	var count = 0
	request := &ddoscoo20200101.DescribeInstancesRequest{}
	request.PageSize = tea.String("30")
	request.PageNumber = tea.String(strconv.Itoa(page))
	for {
		resp, err := cli.DescribeInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeInstances error", zap.Error(err))
			return err
		}

		for _, i := range resp.Body.Instances {
			res <- &DDoSBGPDetail{
				Instance:           i,
				InstanceStatistics: describeInstanceStatistics(ctx, cli, i.InstanceId),
				InstanceSpecs:      describeInstanceSpecs(ctx, cli, i.InstanceId),
				InstanceDetail:     describeInstanceDetails(ctx, cli, i.InstanceId),
			}
		}

		count += len(resp.Body.Instances)
		if count >= int(*resp.Body.TotalCount) {
			break
		}
		page += 1
		request.PageNumber = tea.String(strconv.Itoa(page))
	}
	return nil
}

func describeInstanceStatistics(ctx context.Context, cli *ddoscoo20200101.Client, instanceId *string) *ddoscoo20200101.DescribeInstanceStatisticsResponseBodyInstanceStatistics {
	request := &ddoscoo20200101.DescribeInstanceStatisticsRequest{
		InstanceIds: []*string{instanceId},
	}
	result, err := cli.DescribeInstanceStatistics(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeInstanceStatistics error", zap.Error(err))
		return nil
	}
	return result.Body.InstanceStatistics[0]
}

func describeInstanceSpecs(ctx context.Context, cli *ddoscoo20200101.Client, instanceId *string) *ddoscoo20200101.DescribeInstanceSpecsResponseBodyInstanceSpecs {
	request := &ddoscoo20200101.DescribeInstanceSpecsRequest{
		InstanceIds: []*string{instanceId},
	}
	result, err := cli.DescribeInstanceSpecs(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeInstanceSpecs error", zap.Error(err))
		return nil
	}
	return result.Body.InstanceSpecs[0]
}

func describeInstanceDetails(ctx context.Context, cli *ddoscoo20200101.Client, instanceId *string) *ddoscoo20200101.DescribeInstanceDetailsResponseBodyInstanceDetails {
	request := &ddoscoo20200101.DescribeInstanceDetailsRequest{
		InstanceIds: []*string{instanceId},
	}
	result, err := cli.DescribeInstanceDetails(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeInstanceSpecs error", zap.Error(err))
		return nil
	}
	return result.Body.InstanceDetails[0]
}

type DDoSBGPDetail struct {
	Instance           *ddoscoo20200101.DescribeInstancesResponseBodyInstances
	InstanceStatistics *ddoscoo20200101.DescribeInstanceStatisticsResponseBodyInstanceStatistics
	InstanceSpecs      *ddoscoo20200101.DescribeInstanceSpecsResponseBodyInstanceSpecs
	InstanceDetail     *ddoscoo20200101.DescribeInstanceDetailsResponseBodyInstanceDetails
}
