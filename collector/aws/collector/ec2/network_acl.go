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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/cloudrec/aws/collector/ec2/utils"
)

// GetNetworkAclResource returns a NetworkAcl Resource
func GetNetworkAclResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NetworkAcl,
		ResourceTypeName:   collector.NetworkAcl,
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkAcls.html`,
		ResourceDetailFunc: GetNetworkAclDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ACL.NetworkAclId",
			ResourceName: "$.Name",
		},
		Dimension: schema.Regional,
	}
}

type NetworkACLDetail struct {

	// The NetworkAcl.
	ACL types.NetworkAcl

	// ACL name. Get it from Tags where the key is "Name".
	// Default name is "-"
	Name string
}

func GetNetworkAclDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) error {
	client := iService.(*collector.Services).EC2

	networkAclDetails, err := describeNetworkAclDetails(ctx, client)
	if err != nil {
		return err
	}

	for _, networkAclDetail := range networkAclDetails {
		res <- networkAclDetail
	}

	return nil
}

// describeNetworkAclDetails Describe NetworkAclDetail with all your network ACLs.
// If you want to expand NetworkAclDetail, expand this function.
func describeNetworkAclDetails(ctx context.Context, c *ec2.Client) (networkAclDetails []NetworkACLDetail, err error) {

	networkACLs, err := describeNetworkAcls(ctx, c)
	if err != nil {
		return nil, err
	}

	for _, networkACL := range networkACLs {
		networkAclDetails = append(networkAclDetails, NetworkACLDetail{ACL: networkACL, Name: utils.GetNameFromTags(networkACL.Tags)})
	}

	return networkAclDetails, nil
}

func describeNetworkAcls(ctx context.Context, c *ec2.Client) (networkACLs []types.NetworkAcl, err error) {
	input := &ec2.DescribeNetworkAclsInput{}
	output, err := c.DescribeNetworkAcls(ctx, input)
	if err != nil {
		return nil, err
	}
	networkACLs = append(networkACLs, output.NetworkAcls...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeNetworkAcls(ctx, input)
		if err != nil {
			return nil, err
		}
		networkACLs = append(networkACLs, output.NetworkAcls...)
	}
	return networkACLs, nil
}

func DescribeNetworkAclsByFilters(ctx context.Context, c *ec2.Client, filters []types.Filter) (networkACLs []types.NetworkAcl) {
	input := &ec2.DescribeNetworkAclsInput{
		Filters: filters,
	}
	output, err := c.DescribeNetworkAcls(ctx, input)
	if err != nil {
		return nil
	}
	networkACLs = append(networkACLs, output.NetworkAcls...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeNetworkAcls(ctx, input)
		if err != nil {
			return nil
		}
		networkACLs = append(networkACLs, output.NetworkAcls...)
	}
	return networkACLs
}
