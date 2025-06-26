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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/cloudrec/aws/collector"
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
		Dimension: schema.Global,
	}
}

type RecordSetDetailDetail struct {
	HostedZone types.HostedZone

	ResourceRecordSets []types.ResourceRecordSet
}

func GetResourceRecordSetDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Route53

	domainRRDetails, err := describeDomainRRDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeDomainRRDetails error", zap.Error(err))
		return err
	}

	for _, domainRRDetail := range domainRRDetails {
		res <- domainRRDetail
	}

	return nil
}

func describeDomainRRDetails(ctx context.Context, c *route53.Client) (domainRRDetails []RecordSetDetailDetail, err error) {

	hostedZones, err := listHostedZones(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("listHostedZones error", zap.Error(err))
		return nil, err
	}

	for _, hostedZone := range hostedZones {
		domainRRDetails = append(domainRRDetails, RecordSetDetailDetail{
			HostedZone:         hostedZone,
			ResourceRecordSets: listResourceRecordSets(ctx, c, hostedZone),
		})
	}

	return domainRRDetails, nil
}

func listResourceRecordSets(ctx context.Context, c *route53.Client, hostZone types.HostedZone) (resourceRecordSets []types.ResourceRecordSet) {

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: hostZone.Id,
	}
	output, err := c.ListResourceRecordSets(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("listResourceRecordSets error", zap.Error(err))
		return nil
	}
	resourceRecordSets = append(resourceRecordSets, output.ResourceRecordSets...)
	for output.IsTruncated {
		input.StartRecordIdentifier = output.NextRecordIdentifier
		output, err = c.ListResourceRecordSets(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("listResourceRecordSets error", zap.Error(err))
			return nil
		}
		resourceRecordSets = append(resourceRecordSets, output.ResourceRecordSets...)
	}

	return resourceRecordSets
}

func listHostedZones(ctx context.Context, c *route53.Client) (hostedZones []types.HostedZone, err error) {
	input := &route53.ListHostedZonesInput{}
	output, err := c.ListHostedZones(ctx, input)
	if err != nil {
		return nil, err
	}
	hostedZones = append(hostedZones, output.HostedZones...)
	for output.IsTruncated {
		input.Marker = output.NextMarker
		output, err = c.ListHostedZones(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("listHostedZones error", zap.Error(err))
			return nil, err
		}
		hostedZones = append(hostedZones, output.HostedZones...)
	}

	return hostedZones, nil
}
