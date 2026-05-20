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

	"github.com/aws/aws-sdk-go-v2/aws"
	types2 "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/cloudrec/aws/collector/ec2"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetELBResource returns a  ELB Resource
// ELB is elasticloadbalancingv2
func GetELBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ELB,
		ResourceTypeName:   "ELB",
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html`,
		ResourceDetailFunc: GetELBDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ELB.LoadBalancerArn",
			ResourceName: "$.ELB.LoadBalancerName",
		},
		Dimension: schema.Regional,
	}
}

func GetELBListenerResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ELBListener,
		ResourceTypeName:   "ELB Listener",
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeListeners.html`,
		ResourceDetailFunc: GetELBListenerDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Listener.ListenerArn",
			ResourceName: "$.Listener.ListenerArn",
		},
		Dimension: schema.Regional,
	}
}

type ELBDetail struct {
	ELB types.LoadBalancer

	// Listeners information of the LoadBalancer
	Listeners []types.Listener

	// SecurityGroups information of the LoadBalancer
	SecurityGroups []ec2.SecurityGroupDetail

	// VPC information of the LoadBalancer
	VPC []ec2.VPCDetail
}

type ELBListenerDetail struct {
	Listener types.Listener
}

func GetELBDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) error {
	elbClient := iService.(*collector.Services).ELB
	ec2Client := iService.(*collector.Services).EC2

	return forEachELB(ctx, elbClient, func(elb types.LoadBalancer) error {
		listeners, err := describeELBListenersByLoadBalancerArn(ctx, elbClient, elb.LoadBalancerArn)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeListeners error", zap.Error(err), zap.String("loadBalancerArn", aws.ToString(elb.LoadBalancerArn)))
		}
		res <- ELBDetail{
			ELB:       elb,
			Listeners: listeners,
			VPC: ec2.DescribeVPCDetailsByFilters(ctx, ec2Client, []types2.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*elb.VpcId},
				},
			}),
			SecurityGroups: ec2.DescribeSecurityGroupDetailsByFilters(ctx, ec2Client, []types2.Filter{
				{
					Name:   aws.String("group-id"),
					Values: elb.SecurityGroups,
				},
			}),
		}
		return nil
	})
}

func GetELBListenerDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) error {
	elbClient := iService.(*collector.Services).ELB

	return forEachELB(ctx, elbClient, func(elb types.LoadBalancer) error {
		listeners, err := describeELBListenersByLoadBalancerArn(ctx, elbClient, elb.LoadBalancerArn)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeListeners error", zap.Error(err), zap.String("loadBalancerArn", aws.ToString(elb.LoadBalancerArn)))
			return nil
		}
		for _, listener := range listeners {
			res <- ELBListenerDetail{Listener: listener}
		}
		return nil
	})
}

func describeELBListenersByLoadBalancerArn(ctx context.Context, c *elasticloadbalancingv2.Client, loadBalancerArn *string) (listeners []types.Listener, err error) {
	if loadBalancerArn == nil {
		return listeners, nil
	}
	input := &elasticloadbalancingv2.DescribeListenersInput{
		LoadBalancerArn: loadBalancerArn,
		PageSize:        aws.Int32(400),
	}
	output, err := c.DescribeListeners(ctx, input)
	if err != nil {
		return nil, err
	}
	listeners = append(listeners, output.Listeners...)
	for output.NextMarker != nil {
		input.Marker = output.NextMarker
		output, err = c.DescribeListeners(ctx, input)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, output.Listeners...)
	}
	return listeners, nil
}

func forEachELB(ctx context.Context, c *elasticloadbalancingv2.Client, handle func(types.LoadBalancer) error) error {
	input := &elasticloadbalancingv2.DescribeLoadBalancersInput{
		PageSize: aws.Int32(400),
	}
	for {
		output, err := c.DescribeLoadBalancers(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
			return err
		}
		for _, elb := range output.LoadBalancers {
			if err := handle(elb); err != nil {
				return err
			}
		}
		if output.NextMarker == nil {
			return nil
		}
		input.Marker = output.NextMarker
	}
}
