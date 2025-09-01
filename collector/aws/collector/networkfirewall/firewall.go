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

// GetFirewallResource returns AWS Network Firewall resource definition
func GetFirewallResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NetworkFirewall,
		ResourceTypeName:   "Network Firewall",
		ResourceGroupType:  constant.NET,
		Desc:               "https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_Firewall.html",
		ResourceDetailFunc: GetFirewallDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Firewall.FirewallArn",
			ResourceName: "$.Firewall.FirewallName",
		},
		Dimension: schema.Regional,
	}
}

// FirewallDetail aggregates all information for a single Network Firewall.
type FirewallDetail struct {
	Firewall       *types.Firewall
	FirewallStatus *types.FirewallStatus
	UpdateToken    *string
}

// GetFirewallDetail fetches the details for all Network Firewalls in a region.
func GetFirewallDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).NetworkFirewall

	firewalls, err := listFirewalls(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Network Firewalls", zap.Error(err))
		return err
	}

	for _, firewall := range firewalls {
		describeFirewallOutput := describeFirewall(ctx, client, firewall)
		if describeFirewallOutput == nil {
			continue
		}

		res <- &FirewallDetail{
			Firewall:       describeFirewallOutput.Firewall,
			FirewallStatus: describeFirewallOutput.FirewallStatus,
			UpdateToken:    describeFirewallOutput.UpdateToken,
		}
	}

	return nil
}

// listFirewalls retrieves all Network Firewalls in a region.
func listFirewalls(ctx context.Context, c *networkfirewall.Client) ([]types.FirewallMetadata, error) {
	var firewalls []types.FirewallMetadata
	input := &networkfirewall.ListFirewallsInput{
		MaxResults: aws.Int32(100),
	}

	paginator := networkfirewall.NewListFirewallsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		firewalls = append(firewalls, page.Firewalls...)
	}
	return firewalls, nil
}

func describeFirewall(ctx context.Context, client *networkfirewall.Client, firewall types.FirewallMetadata) *networkfirewall.DescribeFirewallOutput {
	// Get detailed firewall information
	input := &networkfirewall.DescribeFirewallInput{
		FirewallArn: firewall.FirewallArn,
	}
	output, err := client.DescribeFirewall(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe Network Firewall", zap.String("arn", *firewall.FirewallArn), zap.Error(err))
		return nil
	}

	return output
}
