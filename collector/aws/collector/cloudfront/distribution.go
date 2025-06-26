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

package cloudfront

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/cloudrec/aws/collector"
	"go.uber.org/zap"

	"context"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// GetDistributionResource returns a Distribution Resource
func GetDistributionResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CDN,
		ResourceTypeName:   "CDN",
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html`,
		ResourceDetailFunc: GetDistributionDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Distribution.Id",
			ResourceName: "$.Distribution.DomainName",
		},
		Dimension: schema.Global,
	}
}

type DistributionDetail struct {
	Distribution types.DistributionSummary
}

func GetDistributionDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CloudFront

	distributionDetails, err := describeDistributionDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeDistributionDetails error", zap.Error(err))
		return err
	}

	for _, distributionDetail := range distributionDetails {
		res <- distributionDetail
	}

	return nil
}

func describeDistributionDetails(ctx context.Context, c *cloudfront.Client) (distributionDetails []DistributionDetail, err error) {

	distributions, err := listDistributions(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("listDistributions error", zap.Error(err))
		return nil, err
	}

	for _, distribution := range distributions {
		distributionDetails = append(distributionDetails, DistributionDetail{
			Distribution: distribution,
		})
	}

	return distributionDetails, nil
}

func listDistributions(ctx context.Context, c *cloudfront.Client) (distributions []types.DistributionSummary, err error) {
	input := &cloudfront.ListDistributionsInput{}
	output, err := c.ListDistributions(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("listDistributions error", zap.Error(err))
		return nil, err
	}
	distributions = append(distributions, output.DistributionList.Items...)
	for *output.DistributionList.IsTruncated {
		input.Marker = output.DistributionList.NextMarker
		output, err = c.ListDistributions(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("listDistributions error", zap.Error(err))
			return nil, err
		}
		distributions = append(distributions, output.DistributionList.Items...)
	}

	return distributions, nil
}
