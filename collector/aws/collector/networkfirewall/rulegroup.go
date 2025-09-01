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

package networkfirewall

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetRuleGroupResource returns AWS Network Firewall Rule Group resource definition
func GetRuleGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NetworkFirewall,
		ResourceTypeName:   "Network Firewall Rule Group",
		ResourceGroupType:  constant.NET,
		Desc:               "https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_RuleGroup.html",
		ResourceDetailFunc: GetRuleGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.RuleGroup.RuleGroupResponse.Arn",
			ResourceName: "$.RuleGroup.RuleGroupResponse.Name",
		},
		Dimension: schema.Regional,
	}
}

// RuleGroupDetail aggregates all information for a single Network Firewall Rule Group.
type RuleGroupDetail struct {
	RuleGroupResponse *types.RuleGroupResponse
	UpdateToken       *string
	RuleGroup         *types.RuleGroup
}

// GetRuleGroupDetail fetches the details for all Network Firewall Rule Groups in a region.
func GetRuleGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).NetworkFirewall

	ruleGroups, err := listRuleGroups(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Network Firewall Rule Groups", zap.Error(err))
		return err
	}

	for _, ruleGroup := range ruleGroups {
		describeRuleGroupOutput := describeRuleGroup(ctx, client, ruleGroup)
		if describeRuleGroupOutput == nil {
			continue
		}

		res <- &RuleGroupDetail{
			RuleGroupResponse: describeRuleGroupOutput.RuleGroupResponse,
			UpdateToken:       describeRuleGroupOutput.UpdateToken,
			RuleGroup:         describeRuleGroupOutput.RuleGroup,
		}
	}
	return nil
}

// listRuleGroups retrieves all Network Firewall Rule Groups in a region.
func listRuleGroups(ctx context.Context, c *networkfirewall.Client) ([]types.RuleGroupMetadata, error) {
	var ruleGroups []types.RuleGroupMetadata
	input := &networkfirewall.ListRuleGroupsInput{
		MaxResults: aws.Int32(100),
	}

	paginator := networkfirewall.NewListRuleGroupsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		ruleGroups = append(ruleGroups, page.RuleGroups...)
	}
	return ruleGroups, nil
}

func describeRuleGroup(ctx context.Context, client *networkfirewall.Client, ruleGroup types.RuleGroupMetadata) *networkfirewall.DescribeRuleGroupOutput {
	// Get detailed rule group information
	describeInput := &networkfirewall.DescribeRuleGroupInput{
		RuleGroupArn: ruleGroup.Arn,
	}
	describeOutput, err := client.DescribeRuleGroup(ctx, describeInput)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe Network Firewall Rule Group", zap.String("arn", *ruleGroup.Arn), zap.Error(err))
		return nil
	}

	return describeOutput
}
