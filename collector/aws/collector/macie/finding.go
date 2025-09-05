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

package macie

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetFindingResource returns AWS Macie finding resource definition
func GetFindingResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MacieFinding,
		ResourceTypeName:   "Macie Finding",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/macie/latest/APIReference/findings.html",
		ResourceDetailFunc: GetFindingDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Finding.Id",
			ResourceName: "$.Finding.Title",
		},
		Dimension: schema.Regional,
	}
}

// FindingDetail aggregates all information for a single Macie finding.
type FindingDetail struct {
	Finding types.Finding
	Tags    map[string]string
}

// GetFindingDetail fetches the details for all Macie findings in a region.
func GetFindingDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Macie

	findings, err := listFindings(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Macie findings", zap.Error(err))
		return err
	}

	for _, finding := range findings {
		findingDetail := describeFindingDetail(ctx, client, finding)
		res <- findingDetail
	}

	return nil
}

// listFindings retrieves all Macie findings in a region.
func listFindings(ctx context.Context, c *macie2.Client) ([]types.Finding, error) {
	var findings []types.Finding
	input := &macie2.ListFindingsInput{
		MaxResults: aws.Int32(50),
	}

	paginator := macie2.NewListFindingsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		// Get detailed finding information
		if len(page.FindingIds) > 0 {
			getInput := &macie2.GetFindingsInput{
				FindingIds: page.FindingIds,
			}
			getOutput, err := c.GetFindings(ctx, getInput)
			if err != nil {
				return nil, err
			}
			findings = append(findings, getOutput.Findings...)
		}
	}
	return findings, nil
}

// describeFindingDetail fetches all details for a single finding.
func describeFindingDetail(ctx context.Context, client *macie2.Client, finding types.Finding) *FindingDetail {
	var tags map[string]string

	// Get tags - Macie findings don't typically have direct tags,
	// but we can extract relevant information from the finding itself
	tags = extractFindingTags(&finding)

	return &FindingDetail{
		Finding: finding,
		Tags:    tags,
	}
}

// extractFindingTags extracts relevant information from a finding as tags
func extractFindingTags(finding *types.Finding) map[string]string {
	tags := make(map[string]string)

	// Extract some key information from the finding as tags
	if finding.Id != nil {
		tags["FindingId"] = *finding.Id
	}

	tags["Category"] = string(finding.Category)

	// Add severity description if available
	if finding.Severity != nil {
		tags["Severity"] = string(finding.Severity.Description)
	}

	// Add classification result if available
	if finding.ClassificationDetails != nil &&
		finding.ClassificationDetails.Result != nil &&
		finding.ClassificationDetails.Result.Status != nil &&
		finding.ClassificationDetails.Result.Status.Code != nil {
		tags["ClassificationStatus"] = *finding.ClassificationDetails.Result.Status.Code
	}

	return tags
}
