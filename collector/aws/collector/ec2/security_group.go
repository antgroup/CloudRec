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
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
	"go.uber.org/zap"
)

// GetSecurityGroupResource returns a SecurityGroup Resource
func GetSecurityGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SecurityGroup,
		ResourceTypeName:   collector.SecurityGroup,
		ResourceGroupType:  constant.COMPUTE,
		Desc:               `https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html`,
		ResourceDetailFunc: GetSecurityGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.SecurityGroup.GroupId",
			ResourceName: "$.SecurityGroup.GroupName",
		},
		Dimension: schema.Regional,
	}
}

type SecurityGroupDetail struct {

	// SecurityGroup information
	SecurityGroup types.SecurityGroup

	// SecurityGroupRules information
	SecurityGroupRules []types.SecurityGroupRule
}

func GetSecurityGroupDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) (err error) {
	client := iService.(*collector.Services).EC2

	securityGroupDetails, err := describeSecurityGroupDetails(ctx, client)
	if err != nil {
		return err
	}

	for _, securityGroupDetail := range securityGroupDetails {
		res <- securityGroupDetail
	}

	return nil
}

// describeSecurityGroupDetails Describe SecurityGroupDetail with all your security group.
// If you want to expand SecurityGroupDetail, expand this function
func describeSecurityGroupDetails(ctx context.Context, c *ec2.Client) (securityGroupDetails []SecurityGroupDetail, err error) {

	securityGroups, err := describeSecurityGroups(ctx, c)
	if err != nil {
		return nil, err
	}

	for _, securityGroup := range securityGroups {
		securityGroupRules, err := describeSecurityGroupRulesByFilters(ctx, c, []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{*securityGroup.GroupId},
			},
		})
		if err != nil {
			return nil, err
		}
		securityGroupDetails = append(securityGroupDetails, SecurityGroupDetail{
			SecurityGroup:      securityGroup,
			SecurityGroupRules: securityGroupRules,
		})
	}

	return securityGroupDetails, nil
}

func DescribeSecurityGroupDetailsByFilters(ctx context.Context, c *ec2.Client, filters []types.Filter) (securityGroupDetails []SecurityGroupDetail) {

	securityGroups, err := describeSecurityGroupsByFilters(ctx, c, filters)
	if err != nil {
		return nil
	}

	for _, securityGroup := range securityGroups {
		securityGroupRules, err := describeSecurityGroupRulesByFilters(ctx, c, []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{*securityGroup.GroupId},
			},
		})
		if err != nil {
			log.CtxLogger(ctx).Warn("describe security group rule failed", zap.Error(err))
		}
		securityGroupDetails = append(securityGroupDetails, SecurityGroupDetail{
			SecurityGroup:      securityGroup,
			SecurityGroupRules: securityGroupRules,
		})
	}

	return securityGroupDetails
}

func describeSecurityGroupsByFilters(ctx context.Context, c *ec2.Client, filters []types.Filter) (securityGroups []types.SecurityGroup, err error) {
	input := &ec2.DescribeSecurityGroupsInput{Filters: filters}
	output, err := c.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, err
	}
	securityGroups = append(securityGroups, output.SecurityGroups...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeSecurityGroups(ctx, input)
		if err != nil {
			return nil, err
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
	}
	return securityGroups, nil
}

func describeSecurityGroupRulesByFilters(ctx context.Context, c *ec2.Client, filters []types.Filter) (securityGroupRules []types.SecurityGroupRule, err error) {
	input := &ec2.DescribeSecurityGroupRulesInput{
		Filters: filters,
	}
	output, err := c.DescribeSecurityGroupRules(ctx, input)
	if err != nil {
		return nil, err
	}
	securityGroupRules = append(securityGroupRules, output.SecurityGroupRules...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeSecurityGroupRules(ctx, input)
		if err != nil {
			return nil, err
		}
		securityGroupRules = append(securityGroupRules, output.SecurityGroupRules...)
	}
	return securityGroupRules, nil
}

func describeSecurityGroups(ctx context.Context, c *ec2.Client) (securityGroups []types.SecurityGroup, err error) {
	input := &ec2.DescribeSecurityGroupsInput{}
	output, err := c.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, err
	}
	securityGroups = append(securityGroups, output.SecurityGroups...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeSecurityGroups(ctx, input)
		if err != nil {
			return nil, err
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
	}
	return securityGroups, nil
}
