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

// elbv2API is the narrow subset of the elasticloadbalancingv2 client used by
// this collector, declared so the streaming helpers can be exercised with a
// fake in tests. The signatures mirror the SDK exactly so the concrete
// *elasticloadbalancingv2.Client satisfies it.
type elbv2API interface {
	DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
	DescribeListeners(context.Context, *elasticloadbalancingv2.DescribeListenersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error)
}

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

// GetELBDetail streams each ELB detail as the DescribeLoadBalancers
// pagination yields it and its secondary calls finish, so the core-sdk
// consumer in schema/platform.go does not hit the 30s idle timeout when a
// region has many load balancers.
func GetELBDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) error {
	elbClient := iService.(*collector.Services).ELB
	ec2Client := iService.(*collector.Services).EC2

	return streamELBDetails(
		ctx,
		elbClient,
		res,
		func(ctx context.Context, elb types.LoadBalancer) []ec2.VPCDetail {
			if elb.VpcId == nil {
				return nil
			}
			return ec2.DescribeVPCDetailsByFilters(ctx, ec2Client, []types2.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*elb.VpcId},
				},
			})
		},
		func(ctx context.Context, elb types.LoadBalancer) []ec2.SecurityGroupDetail {
			return ec2.DescribeSecurityGroupDetailsByFilters(ctx, ec2Client, []types2.Filter{
				{
					Name:   aws.String("group-id"),
					Values: elb.SecurityGroups,
				},
			})
		},
	)
}

// streamELBDetails paginates DescribeLoadBalancers via forEachELB and pushes
// each ELBDetail as soon as the page yields the LB and its listener call
// returns. The VPC / SecurityGroup enrichment is injected so the streaming
// behaviour can be exercised without an ec2 client; both callbacks are
// non-nil in production and a nil callback simply skips that field.
func streamELBDetails(
	ctx context.Context,
	c elbv2API,
	res chan<- any,
	describeVPCDetails func(context.Context, types.LoadBalancer) []ec2.VPCDetail,
	describeSecurityGroupDetails func(context.Context, types.LoadBalancer) []ec2.SecurityGroupDetail,
) error {
	return forEachELB(ctx, c, func(elb types.LoadBalancer) error {
		listeners, err := describeELBListenersByLoadBalancerArn(ctx, c, elb.LoadBalancerArn)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeListeners error", zap.Error(err), zap.String("loadBalancerArn", aws.ToString(elb.LoadBalancerArn)))
		}
		detail := ELBDetail{
			ELB:       elb,
			Listeners: listeners,
		}
		if describeVPCDetails != nil {
			detail.VPC = describeVPCDetails(ctx, elb)
		}
		if describeSecurityGroupDetails != nil {
			detail.SecurityGroups = describeSecurityGroupDetails(ctx, elb)
		}
		res <- detail
		return nil
	})
}

// GetELBListenerDetail streams each listener per LB as the
// DescribeLoadBalancers pagination yields each LB. Same rationale as
// GetELBDetail — incremental push keeps the consumer's idle timer warm.
func GetELBListenerDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) error {
	elbClient := iService.(*collector.Services).ELB

	return streamELBListeners(ctx, elbClient, res)
}

// streamELBListeners paginates DescribeLoadBalancers via forEachELB and pushes
// each LB's listeners as soon as the page yields the LB.
func streamELBListeners(ctx context.Context, c elbv2API, res chan<- any) error {
	return forEachELB(ctx, c, func(elb types.LoadBalancer) error {
		listeners, err := describeELBListenersByLoadBalancerArn(ctx, c, elb.LoadBalancerArn)
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

func describeELBListenersByLoadBalancerArn(ctx context.Context, c elbv2API, loadBalancerArn *string) (listeners []types.Listener, err error) {
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

// forEachELB paginates DescribeLoadBalancers and invokes handle for each
// load balancer as its page arrives, so callers stream per-LB instead of
// buffering the whole region before the first push. Returns the first list
// error encountered.
func forEachELB(ctx context.Context, c elbv2API, handle func(types.LoadBalancer) error) error {
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
