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

package elasticloadbalancing

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetCLBResource returns a  CLB Resource
// CLB is elasticloadbalancingv1
func GetCLBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CLB,
		ResourceTypeName:   "CLB",
		ResourceGroupType:  constant.NET,
		Desc:               ``,
		ResourceDetailFunc: GetCLBDetail,
		RowField: schema.RowField{
			ResourceId:   "$.LoadBalancer.DNSName",
			ResourceName: "$.LoadBalancer.LoadBalancerName",
			Address:      "$.LoadBalancer.DNSName",
		},
		Dimension: schema.Regional,
	}
}

type CLBDetail struct {
	LoadBalancer types.LoadBalancerDescription
}

func GetCLBDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) error {

	client := iService.(*collector.Services).CLB

	CLBDetails, err := describeCLBDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeCLBDetails error", zap.Error(err))
		return err
	}

	for _, clb := range CLBDetails {
		res <- clb
	}

	return nil
}

func describeCLBDetails(ctx context.Context, c *elasticloadbalancing.Client) (CLBDetails []CLBDetail, err error) {
	clbs, err := describeCLBs(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeCLBs error", zap.Error(err))
		return nil, err
	}
	for _, clb := range clbs {
		CLBDetails = append(CLBDetails, CLBDetail{LoadBalancer: clb})
	}
	return CLBDetails, nil
}

func describeCLBs(ctx context.Context, c *elasticloadbalancing.Client) (clbs []types.LoadBalancerDescription, err error) {
	input := &elasticloadbalancing.DescribeLoadBalancersInput{}
	output, err := c.DescribeLoadBalancers(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
		return nil, err
	}
	clbs = append(clbs, output.LoadBalancerDescriptions...)
	for output.NextMarker != nil {
		input.Marker = output.NextMarker
		output, err = c.DescribeLoadBalancers(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("describeCLBs error", zap.Error(err))
			return nil, err
		}
		clbs = append(clbs, output.LoadBalancerDescriptions...)
	}
	return clbs, nil
}
