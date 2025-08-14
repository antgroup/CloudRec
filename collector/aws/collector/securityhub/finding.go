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

package securityhub

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const maxWorkers = 10

// GetFindingResource returns AWS SecurityHub finding resource definition
func GetFindingResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SecurityHub,
		ResourceTypeName:   "SecurityHub Finding",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html",
		ResourceDetailFunc: GetFindingDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Finding.Id",
			ResourceName: "$.Finding.Title",
		},
		Dimension: schema.Regional,
	}
}

// FindingDetail aggregates all information for a single SecurityHub finding.
type FindingDetail struct {
	Finding types.AwsSecurityFinding
	Tags    map[string]string
}

// GetFindingDetail fetches the details for all SecurityHub findings in a region.
func GetFindingDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).SecurityHub

	findings, err := listFindings(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list SecurityHub findings", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.AwsSecurityFinding, len(findings))

	// Start worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for finding := range tasks {
				detail := describeFindingDetail(ctx, client, finding)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks
	for _, finding := range findings {
		tasks <- finding
	}
	close(tasks)

	wg.Wait()
	return nil
}

// listFindings retrieves all SecurityHub findings in a region.
func listFindings(ctx context.Context, c *securityhub.Client) ([]types.AwsSecurityFinding, error) {
	var findings []types.AwsSecurityFinding
	input := &securityhub.GetFindingsInput{
		MaxResults: aws.Int32(100),
	}

	paginator := securityhub.NewGetFindingsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		findings = append(findings, page.Findings...)
	}
	return findings, nil
}

// describeFindingDetail fetches all details for a single finding.
func describeFindingDetail(ctx context.Context, client *securityhub.Client, finding types.AwsSecurityFinding) *FindingDetail {
	var tags map[string]string

	// Copy the finding to avoid race conditions
	findingCopy := finding

	// Get tags - SecurityHub findings don't typically have direct tags,
	// but we can extract relevant information from the finding itself
	tags = extractFindingTags(&findingCopy)

	return &FindingDetail{
		Finding: findingCopy,
		Tags:    tags,
	}
}

// extractFindingTags extracts relevant information from a finding as tags
func extractFindingTags(finding *types.AwsSecurityFinding) map[string]string {
	tags := make(map[string]string)

	// Extract some key information from the finding as tags
	if finding.ProductArn != nil {
		tags["ProductArn"] = *finding.ProductArn
	}
	
	if finding.GeneratorId != nil {
		tags["GeneratorId"] = *finding.GeneratorId
	}
	
	if finding.SchemaVersion != nil {
		tags["SchemaVersion"] = *finding.SchemaVersion
	}
	
	// Add severity label if available
	if finding.Severity != nil && finding.Severity.Label != "" {
		tags["SeverityLabel"] = string(finding.Severity.Label)
	}
	
	// Add workflow status if available
	if finding.Workflow != nil && finding.Workflow.Status != "" {
		tags["WorkflowStatus"] = string(finding.Workflow.Status)
	}

	return tags
}