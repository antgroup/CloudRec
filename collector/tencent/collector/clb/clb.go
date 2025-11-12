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

	"github.com/cloudrec/tencent/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
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
	SecurityGroupDetail []*vpc.SecurityGroupPolicySet
}

func ListCLBResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	clbClient := services.CLB
	vpcClient := services.VPC

	request := clb.NewDescribeLoadBalancersRequest()
	request.Limit = common.Int64Ptr(100)
	request.Offset = common.Int64Ptr(0)

	var count uint64
	for {
		response, err := clbClient.DescribeLoadBalancers(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
			return err
		}
		for _, lb := range response.Response.LoadBalancerSet {
			d := &LBDetail{
				LoadBalancer: *lb,
				Listeners:    describeTargets(ctx, clbClient, lb.LoadBalancerId),
				SecureGroups: lb.SecureGroups,
				SecurityGroupDetail: describeSecurityGroups(ctx, vpcClient, lb.SecureGroups),
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

func describeSecurityGroups(ctx context.Context, cli *vpc.Client, securityGroupIds []*string) []*vpc.SecurityGroupPolicySet {

	var securityGroupInfo []*vpc.SecurityGroupPolicySet
	for _, securityGroupId := range securityGroupIds {
		request := vpc.NewDescribeSecurityGroupPoliciesRequest()
		request.SecurityGroupId = securityGroupId

		response, err := cli.DescribeSecurityGroupPolicies(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("Describe SecurityGroupPolicies error", zap.Error(err))
			return nil
		}

		securityGroupInfo = append(securityGroupInfo, response.Response.SecurityGroupPolicySet)
	}

	return securityGroupInfo
}