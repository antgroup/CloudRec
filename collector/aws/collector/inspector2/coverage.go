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

package inspector2

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetCoverageResource returns AWS Inspector2 coverage resource definition
func GetCoverageResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Inspector2,
		ResourceTypeName:   "Inspector2 Coverage",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListCoverage.html",
		ResourceDetailFunc: GetCoverageDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Coverage.ResourceId",
			ResourceName: "$.Coverage.ResourceId",
		},
		Dimension: schema.Regional,
	}
}

// CoverageDetail aggregates all information for a single Inspector2 coverage.
type CoverageDetail struct {
	Coverage types.CoveredResource
}

// GetCoverageDetail fetches the details for all Inspector2 coverage in a region.
func GetCoverageDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Inspector2

	coverageList, err := listCoverage(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Inspector2 coverage", zap.Error(err))
		return err
	}

	for _, coverage := range coverageList {
		res <- &CoverageDetail{
			Coverage: coverage,
		}
	}

	return nil
}

// listCoverage retrieves all Inspector2 coverage in a region.
func listCoverage(ctx context.Context, c *inspector2.Client) ([]types.CoveredResource, error) {
	var coverage []types.CoveredResource
	input := &inspector2.ListCoverageInput{
		MaxResults: aws.Int32(100),
	}

	paginator := inspector2.NewListCoveragePaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		coverage = append(coverage, page.CoveredResources...)
	}
	return coverage, nil
}
