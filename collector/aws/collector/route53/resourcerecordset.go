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

package route53

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetResourceRecordSetResource returns a ResourceRecordSet Resource
func GetResourceRecordSetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ResourceRecordSet,
		ResourceTypeName:   collector.ResourceRecordSet,
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html`,
		ResourceDetailFunc: GetResourceRecordSetDetail,
		RowField: schema.RowField{
			ResourceId:   "$.HostedZone.Id",
			ResourceName: "$.HostedZone.Name",
			Address:      "",
		},
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

type RecordSetDetailDetail struct {
	HostedZone types.HostedZone

	ResourceRecordSets []types.ResourceRecordSet
}

// GetResourceRecordSetDetail streams each hosted zone as the
// ListHostedZones pagination yields it; the per-zone
// ListResourceRecordSets calls then stream their record sets. This
// incremental push avoids the 30s consumer idle timeout in core-sdk
// schema/platform.go when an account has many hosted zones.
func GetResourceRecordSetDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Route53

	input := &route53.ListHostedZonesInput{}
	for {
		output, err := client.ListHostedZones(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("listHostedZones error", zap.Error(err))
			return err
		}
		for _, hostedZone := range output.HostedZones {
			res <- RecordSetDetailDetail{
				HostedZone:         hostedZone,
				ResourceRecordSets: listResourceRecordSets(ctx, client, hostedZone),
			}
		}
		if !output.IsTruncated {
			return nil
		}
		input.Marker = output.NextMarker
	}
}

func listResourceRecordSets(ctx context.Context, c *route53.Client, hostZone types.HostedZone) (resourceRecordSets []types.ResourceRecordSet) {
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: hostZone.Id,
	}
	paginator := route53.NewListResourceRecordSetsPaginator(c, input)

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("listResourceRecordSets error", zap.Error(err))
			return nil
		}
		resourceRecordSets = append(resourceRecordSets, output.ResourceRecordSets...)
	}

	return resourceRecordSets
}
