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

// GetFindingResource returns AWS Inspector2 finding resource definition
func GetFindingResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Inspector2,
		ResourceTypeName:   "Inspector2 Finding",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html",
		ResourceDetailFunc: GetFindingDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Finding.FindingArn",
			ResourceName: "$.Finding.Title",
		},
		Dimension: schema.Regional,
	}
}

// FindingDetail aggregates all information for a single Inspector2 finding.
type FindingDetail struct {
	Finding types.Finding
	Tags    map[string]string
}

// GetFindingDetail fetches the details for all Inspector2 findings in a region.
func GetFindingDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Inspector2

	findings, err := listFindings(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Inspector2 findings", zap.Error(err))
		return err
	}

	for _, finding := range findings {
		tags, err := listFindingTags(ctx, client, finding.FindingArn)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list finding tags", zap.String("findingArn", *finding.FindingArn), zap.Error(err))
		}

		res <- &FindingDetail{
			Finding: finding,
			Tags:    tags,
		}
	}

	return nil
}

// listFindings retrieves all Inspector2 findings in a region.
func listFindings(ctx context.Context, c *inspector2.Client) ([]types.Finding, error) {
	var findings []types.Finding
	input := &inspector2.ListFindingsInput{
		MaxResults: aws.Int32(100),
	}

	paginator := inspector2.NewListFindingsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		findings = append(findings, page.Findings...)
	}
	return findings, nil
}

// listFindingTags retrieves tags for a single finding.
func listFindingTags(ctx context.Context, c *inspector2.Client, findingArn *string) (map[string]string, error) {
	input := &inspector2.ListTagsForResourceInput{
		ResourceArn: findingArn,
	}
	output, err := c.ListTagsForResource(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for finding", zap.String("findingArn", *findingArn), zap.Error(err))
		return make(map[string]string), err
	}

	tags := make(map[string]string)
	for key, value := range output.Tags {
		tags[key] = value
	}
	return tags, nil
}
