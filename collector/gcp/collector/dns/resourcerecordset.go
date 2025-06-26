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

package dns

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/gcp/collector"
	"github.com/turbot/go-kit/types"
	"go.uber.org/zap"
	"google.golang.org/api/dns/v1"
)

func GetResourceRecordSetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.ResourceRecordSet,
		ResourceTypeName:  collector.ResourceRecordSet,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.google.com/dns/docs/reference/rest/v1/resourceRecordSets`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).DNSService
			projects := service.(*collector.Services).Projects

			for _, project := range projects {
				projectId := project.ProjectId
				zones, err := listManagedZone(svc, projectId)
				if err != nil || len(zones) == 0 {
					log.CtxLogger(ctx).Warn("listManagedZone err", zap.Error(err))
					continue
				}

				pageSize := types.Int64(1000)
				for _, zone := range zones {
					resp, err := svc.ResourceRecordSets.List(projectId, zone.Name).MaxResults(*pageSize).Do()
					if err != nil {
						log.CtxLogger(ctx).Warn("listResourceRecordSets err", zap.Error(err))
						continue
					}

					for _, record := range resp.Rrsets {
						res <- &DomainRRDetail{RRSet: record}
					}
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.RRSet.name",
			ResourceName: "$.RRSet.name",
		},
		Dimension: schema.Global,
	}
}

func listManagedZone(DNSService *dns.Service, projectId string) (managedZones []*dns.ManagedZone, err error) {

	pageSize := types.Int64(1000)
	ManagedZonesListCall := DNSService.ManagedZones.List(projectId).MaxResults(*pageSize)
	resp, err := ManagedZonesListCall.Do()
	if err != nil {
		return nil, err
	}

	managedZones = append(managedZones, resp.ManagedZones...)
	return
}

type DomainRRDetail struct {
	RRSet *dns.ResourceRecordSet
}
