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

package accessanalyzer

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetAnalyzerResource returns AWS Access Analyzer resource definition
func GetAnalyzerResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.AccessAnalyzer,
		ResourceTypeName:   "Access Analyzer",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/accessanalyzer/latest/APIReference/API_ListAnalyzers.html",
		ResourceDetailFunc: GetAnalyzerDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Analyzer.Arn",
			ResourceName: "$.Analyzer.Name",
		},
		Dimension: schema.Regional,
	}
}

// AnalyzerDetail aggregates all information for a single Access Analyzer.
type AnalyzerDetail struct {
	Analyzer types.AnalyzerSummary
	Findings []types.FindingSummary
	Tags     map[string]string
}

// GetAnalyzerDetail fetches the details for all Access Analyzers in a region.
func GetAnalyzerDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).AccessAnalyzer

	analyzers, err := listAnalyzers(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Access Analyzers", zap.Error(err))
		return err
	}

	for _, analyzer := range analyzers {
		findings, _ := listFindings(ctx, client, analyzer.Arn)
		tags, _ := listAnalyzerTags(ctx, client, analyzer.Arn)
		res <- &AnalyzerDetail{
			Analyzer: analyzer,
			Findings: findings,
			Tags:     tags,
		}
	}

	return nil
}

// listAnalyzers retrieves all Access Analyzers in a region.
func listAnalyzers(ctx context.Context, c *accessanalyzer.Client) ([]types.AnalyzerSummary, error) {
	var analyzers []types.AnalyzerSummary
	input := &accessanalyzer.ListAnalyzersInput{}

	paginator := accessanalyzer.NewListAnalyzersPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		analyzers = append(analyzers, page.Analyzers...)
	}
	return analyzers, nil
}

// listFindings retrieves findings for a single analyzer.
func listFindings(ctx context.Context, c *accessanalyzer.Client, analyzerArn *string) ([]types.FindingSummary, error) {
	var findings []types.FindingSummary
	input := &accessanalyzer.ListFindingsInput{
		AnalyzerArn: analyzerArn,
	}

	paginator := accessanalyzer.NewListFindingsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list findings", zap.String("analyzerArn", *analyzerArn), zap.Error(err))
			return nil, err
		}
		findings = append(findings, page.Findings...)
	}
	return findings, nil
}

// listAnalyzerTags retrieves tags for a single analyzer.
func listAnalyzerTags(ctx context.Context, c *accessanalyzer.Client, analyzerArn *string) (map[string]string, error) {
	input := &accessanalyzer.ListTagsForResourceInput{
		ResourceArn: analyzerArn,
	}
	output, err := c.ListTagsForResource(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for analyzer", zap.String("analyzerArn", *analyzerArn), zap.Error(err))
		return make(map[string]string), err
	}

	tags := make(map[string]string)
	for key, value := range output.Tags {
		if value != "" {
			tags[key] = value
		}
	}
	return tags, nil
}
