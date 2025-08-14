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
	"sync"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	swas "github.com/aliyun/alibaba-cloud-sdk-go/services/swas-open"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const maxWorkers = 10

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
	Instance      *swas.Instance
	FirewallRules []swas.FirewallRule
}

// ListInstancesResource gets SWAS instance details
func ListInstancesResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).SWAS
	req := swas.CreateListInstancesRequest()
	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)

	count := 0
	for {
		resp, err := cli.ListInstances(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstances error", zap.Error(err))
			return err
		}

		var wg sync.WaitGroup
		tasks := make(chan swas.Instance, len(resp.Instances))

		// 启动工作协程
		for i := 0; i < maxWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for instance := range tasks {
					d := &Detail{
						Instance:      &instance,
						FirewallRules: listFirewallRules(ctx, cli, instance.InstanceId),
					}

					res <- d
				}
			}()
		}

		// 添加任务
		for _, instance := range resp.Instances {
			tasks <- instance
		}
		close(tasks)

		wg.Wait()

		count += len(resp.Instances)
		if count >= resp.TotalCount || len(resp.Instances) == 0 {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return nil
}

// listFirewallRules gets firewall rules for a specific instance
func listFirewallRules(ctx context.Context, client *swas.Client, instanceId string) (firewallRules []swas.FirewallRule) {
	req := swas.CreateListFirewallRulesRequest()
	req.InstanceId = instanceId
	req.PageSize = requests.NewInteger(constant.DefaultPageSize)
	req.PageNumber = requests.NewInteger(1)

	count := 0
	for {
		resp, err := client.ListFirewallRules(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListFirewallRules error", zap.Error(err))
			break
		}

		firewallRules = append(firewallRules, resp.FirewallRules...)
		count += len(resp.FirewallRules)

		if count >= resp.TotalCount || len(resp.FirewallRules) < constant.DefaultPageSize {
			break
		}
		req.PageNumber = requests.NewInteger(resp.PageNumber + 1)
	}

	return firewallRules
}
