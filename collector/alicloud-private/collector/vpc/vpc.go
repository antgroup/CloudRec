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

package vpc

import (
	"github.com/alicloud-sqa/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"go.uber.org/zap"
)

func GetVPCResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.VPC,
		ResourceTypeName:   collector.VPC,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Vpc`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Vpc.VpcId",
			ResourceName: "$.Vpc.VpcName",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Vpc          *vpc.Vpc
	VpcAttribute *vpc.DescribeVpcAttributeResponse
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPCClient
	req := vpc.CreateDescribeVpcsRequest()
	req.QueryParams["product"] = "Vpc"
	req.SetHTTPSInsecure(true)
	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		resp, err := cli.DescribeVpcs(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeVpcs error", zap.Error(err))
			return err
		}
		count += len(resp.Vpcs.Vpc)
		for _, v := range resp.Vpcs.Vpc {
			d := &Detail{
				Vpc:          &v,
				VpcAttribute: describeVpcAttribute(ctx, cli, v.VpcId),
			}

			res <- d
		}
		if count >= resp.TotalCount || len(resp.Vpcs.Vpc) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return nil
}

func describeVpcAttribute(ctx context.Context, client *vpc.Client, instanceId string) (response *vpc.DescribeVpcAttributeResponse) {
	request := vpc.CreateDescribeVpcAttributeRequest()
	request.VpcId = instanceId

	request.Scheme = "https"
	response, err := client.DescribeVpcAttribute(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeVpcAttribute error", zap.Error(err))
		return nil
	}
	return response
}
