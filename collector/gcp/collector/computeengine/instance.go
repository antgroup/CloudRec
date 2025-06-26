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

package computeengine

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"fmt"
	"github.com/cloudrec/gcp/collector"
	"go.uber.org/zap"
	"google.golang.org/api/compute/v1"
	"strings"
)

func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.Instance,
		ResourceTypeName:  collector.Instance,
		ResourceGroupType: constant.COMPUTE,
		Desc:              `https://cloud.google.com/compute/docs/reference/rest/v1/instances`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			projects := service.(*collector.Services).Projects
			svc := service.(*collector.Services).ComputeService

			for _, project := range projects {
				projectId := project.ProjectId
				resp := svc.Instances.AggregatedList(projectId).MaxResults(100)
				if err := resp.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
					for _, item := range page.Items {
						for _, instance := range item.Instances {
							instance.Metadata = nil
							detail := Detail{
								Instance:           instance,
								EffectiveFirewalls: GetEffectiveFirewalls(svc, projectId, instance),
								IAMPolicy:          getIamPolicy(svc, projectId, parseZones(instance.Zone), instance.Name),
							}
							res <- detail
						}
					}
					return nil
				}); err != nil {
					log.CtxLogger(ctx).Warn("GetInstanceResource error", zap.Error(err))
					continue
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Instance.id",
			ResourceName: "$.Instance.name",
		},
		Dimension: schema.Global,
	}
}

func parseZones(zone string) string {
	// https://www.googleapis.com/compute/v1/projects/intense-emblem-404402/zones/us-east1-b
	if strings.Contains(zone, "zones/") {
		split := strings.Split(zone, "zones/")
		return split[1]
	}
	return zone
}

func getIamPolicy(svc *compute.Service, project string, zone string, resource string) *compute.Policy {
	policy, err := svc.Instances.GetIamPolicy(project, zone, resource).Do()
	if err != nil {
		log.GetWLogger().Error(fmt.Sprintf("Failed to get iam policy: %s", err))
	}
	return policy
}

type Detail struct {
	Instance           *compute.Instance
	EffectiveFirewalls []*compute.InstancesGetEffectiveFirewallsResponse
	IAMPolicy          *compute.Policy
}

func GetEffectiveFirewalls(computeService *compute.Service, projectId string, instance *compute.Instance) (firewalls []*compute.InstancesGetEffectiveFirewallsResponse) {
	for _, networkInterface := range instance.NetworkInterfaces {
		zone := parseValue(instance.Zone)
		if zone == "" {
			continue
		}
		resp, err := computeService.Instances.GetEffectiveFirewalls(projectId, zone, instance.Name, networkInterface.Name).Do()
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("Failed to Get Effective Firewalls: %v", err))
			return
		}

		firewalls = append(firewalls, resp)
	}

	return
}

func parseValue(url string) string {
	lastSlashIndex := strings.LastIndex(url, "/")
	if lastSlashIndex != -1 {
		extracted := url[lastSlashIndex+1:]
		return extracted
	}

	return ""
}
