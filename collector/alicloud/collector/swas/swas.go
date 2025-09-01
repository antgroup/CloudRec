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

package swas

import (
	"context"
	swas_open20200601 "github.com/alibabacloud-go/swas-open-20200601/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetInstanceResource returns SWAS instance resource definition
func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SWAS,
		ResourceTypeName:   "SWAS",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://next.api.aliyun.com/product/SWAS-Open",
		ResourceDetailFunc: ListInstancesResource,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Dimension: schema.Regional,
	}
}

// Detail aggregates SWAS instance and firewall rule information
type Detail struct {
	Instance      *swas_open20200601.ListInstancesResponseBodyInstances
	FirewallRules []*swas_open20200601.ListFirewallRulesResponseBodyFirewallRules
}

// ListInstancesResource gets SWAS instance details
func ListInstancesResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).SWAS

	instances, err := listInstances(ctx, cli)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListInstances error", zap.Error(err))
		return err
	}

	for _, instance := range instances {
		firewallRules := listFirewallRules(ctx, cli, instance.InstanceId)
		res <- &Detail{
			Instance:      instance,
			FirewallRules: firewallRules,
		}
	}

	return nil
}

// listInstances lists all swas instances in a region.
func listInstances(ctx context.Context, cli *swas_open20200601.Client) (instances []*swas_open20200601.ListInstancesResponseBodyInstances, err error) {
	request := &swas_open20200601.ListInstancesRequest{
		PageNumber: tea.Int32(1),
		PageSize:   tea.Int32(50),
	}

	count := 0
	for {
		resp, err := cli.ListInstances(request)
		if err != nil {
			return nil, err
		}

		instances = append(instances, resp.Body.Instances...)

		count += len(resp.Body.Instances)
		if count >= int(*resp.Body.TotalCount) || len(resp.Body.Instances) == 0 {
			break
		}
		request.PageNumber = tea.Int32(*request.PageNumber + 1)
	}

	return instances, nil
}

// listFirewallRules gets firewall rules for a specific instance
func listFirewallRules(ctx context.Context, client *swas_open20200601.Client, instanceId *string) (firewallRules []*swas_open20200601.ListFirewallRulesResponseBodyFirewallRules) {

	count := 0
	for {
		request := &swas_open20200601.ListFirewallRulesRequest{
			InstanceId: instanceId,
		}
		resp, err := client.ListFirewallRules(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListFirewallRules error", zap.Error(err))
			break
		}

		firewallRules = append(firewallRules, resp.Body.FirewallRules...)
		count += len(resp.Body.FirewallRules)

		if count >= int(*resp.Body.TotalCount) || len(resp.Body.FirewallRules) == 0 {
			break
		}
		request.PageNumber = tea.Int32(*request.PageNumber + 1)
	}

	return firewallRules
}
