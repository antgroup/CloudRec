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

package ec2

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/cloudrec/aws/collector/ec2/utils"
)

// GetVPCResource returns a VPC Resource
func GetVPCResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Vpc,
		ResourceTypeName:   collector.Vpc,
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html`,
		ResourceDetailFunc: GetVPCDetail,
		RowField: schema.RowField{
			ResourceId:   "$.VPC.VpcId",
			ResourceName: "$.Name",
		},
		Dimension: schema.Regional,
	}
}

type VPCDetail struct {

	// The VPC.
	VPC types.Vpc

	// VPC name. Get it from Tags where the key is "Name".
	// Default name is "-"
	Name string

	Subnets []types.Subnet

	ACLs []types.NetworkAcl

	NatGateways []types.NatGateway

	RouteTables []types.RouteTable

	InternetGateways []types.InternetGateway
}

func GetVPCDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) error {
	client := iService.(*collector.Services).EC2

	VPCDetails, err := describeVPCDetails(ctx, client)
	if err != nil {
		return err
	}

	for _, vpc := range VPCDetails {
		res <- vpc
	}

	return nil
}

// describeVPCDetails Describe VPCDetail with all your vpc.
// // If you want to expand VPCDetail, expand this function.
func describeVPCDetails(ctx context.Context, c *ec2.Client) (VPCDetails []VPCDetail, err error) {

	vpcs, err := describeVpcs(ctx, c)
	if err != nil {
		return nil, err
	}

	for _, vpc := range vpcs {
		VPCDetails = append(VPCDetails, VPCDetail{
			VPC:  vpc,
			Name: utils.GetNameFromTags(vpc.Tags),
			Subnets: DescribeSubnetsByFilters(ctx, c, []types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*vpc.VpcId},
				},
			}),
			ACLs: DescribeNetworkAclsByFilters(ctx, c, []types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*vpc.VpcId},
				},
			}),
		})
	}
	return VPCDetails, nil
}

func DescribeVPCDetailsByFilters(ctx context.Context, c *ec2.Client, filters []types.Filter) (VPCDetails []VPCDetail) {

	vpcs := DescribeVpcsByFilters(ctx, c, filters)
	if len(vpcs) == 0 {
		return nil
	}
	for _, vpc := range vpcs {
		VPCDetails = append(VPCDetails, VPCDetail{
			VPC:  vpc,
			Name: utils.GetNameFromTags(vpc.Tags),
			Subnets: DescribeSubnetsByFilters(ctx, c, []types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*vpc.VpcId},
				},
			}),
			ACLs: DescribeNetworkAclsByFilters(ctx, c, []types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*vpc.VpcId},
				},
			}),
		})
	}
	return VPCDetails
}

func DescribeSubnetsByFilters(ctx context.Context, c *ec2.Client, filters []types.Filter) (subnets []types.Subnet) {

	MaxResults := int32(100)

	input := &ec2.DescribeSubnetsInput{
		Filters:    filters,
		MaxResults: &MaxResults,
	}
	output, err := c.DescribeSubnets(ctx, input)
	if err != nil {
		return nil
	}

	return output.Subnets
}

func describeVpcs(ctx context.Context, c *ec2.Client) (vpcs []types.Vpc, err error) {
	input := &ec2.DescribeVpcsInput{}
	output, err := c.DescribeVpcs(ctx, input)
	if err != nil {
		return nil, err
	}
	vpcs = append(vpcs, output.Vpcs...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeVpcs(ctx, input)
		if err != nil {
			return nil, err
		}
		vpcs = append(vpcs, output.Vpcs...)
	}
	return vpcs, nil
}

func DescribeVpcsByFilters(ctx context.Context, c *ec2.Client, filters []types.Filter) (vpcs []types.Vpc) {
	input := &ec2.DescribeVpcsInput{
		Filters: filters,
	}
	output, err := c.DescribeVpcs(ctx, input)
	if err != nil {
		return nil
	}
	vpcs = append(vpcs, output.Vpcs...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeVpcs(ctx, input)
		if err != nil {
			return nil
		}
		vpcs = append(vpcs, output.Vpcs...)
	}
	return vpcs
}
