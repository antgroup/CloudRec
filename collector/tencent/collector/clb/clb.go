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

package clb

import (
	"context"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/cloudrec/tencent/collector"
	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"go.uber.org/zap"
)

func GetCLBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CLB,
		ResourceTypeName:   "CLB",
		ResourceGroupType:  constant.NET,
		Desc:               "https://cloud.tencent.com/document/api/1108/48459",
		ResourceDetailFunc: ListCLBResource,
		RowField: schema.RowField{
			ResourceId:   "$.LoadBalancer.LoadBalancerId",
			ResourceName: "$.LoadBalancer.LoadBalancerName",
			Address:      "$.LoadBalancer.Domain",
		},
		Dimension: schema.Regional,
	}
}

type LBDetail struct {
	LoadBalancer clb.LoadBalancer
	Listeners    []*clb.ListenerBackend
	SecureGroups []*string
}

func ListCLBResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CLB

	request := clb.NewDescribeLoadBalancersRequest()
	request.Limit = common.Int64Ptr(100)
	request.Offset = common.Int64Ptr(0)

	var count uint64
	for {
		response, err := cli.DescribeLoadBalancers(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
			return err
		}
		for _, lb := range response.Response.LoadBalancerSet {
			d := &LBDetail{
				LoadBalancer: *lb,
				Listeners:    describeTargets(ctx, cli, lb.LoadBalancerId),
				SecureGroups: lb.SecureGroups,
			}
			res <- d
		}
		count += uint64(len(response.Response.LoadBalancerSet))
		if count >= *response.Response.TotalCount {
			break
		}
		*request.Offset += *request.Limit
	}

	return nil
}

func describeTargets(ctx context.Context, cli *clb.Client, LoadBalancerId *string) (listeners []*clb.ListenerBackend) {

	request := clb.NewDescribeTargetsRequest()
	request.LoadBalancerId = common.StringPtr(*LoadBalancerId)

	response, err := cli.DescribeTargets(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeTargets error", zap.Error(err))
		return
	}
	return response.Response.Listeners
}
