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

package opensearch

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetDomainResource returns AWS OpenSearch domain resource definition
func GetDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.OpenSearch,
		ResourceTypeName:   "OpenSearch Domain",
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainStatus.html",
		ResourceDetailFunc: GetDomainDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DomainStatus.DomainId",
			ResourceName: "$.DomainStatus.DomainName",
		},
		Dimension: schema.Regional,
	}
}

// DomainDetail aggregates all information for a single OpenSearch domain.
type DomainDetail struct {
	DomainStatus *types.DomainStatus
}

// GetDomainDetail fetches the details for all OpenSearch domains in a region.
func GetDomainDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).OpenSearch

	domains, err := listDomains(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list OpenSearch domains", zap.Error(err))
		return err
	}

	for _, domain := range domains {
		describeOutput := describeDomain(ctx, client, domain)
		res <- DomainDetail{
			DomainStatus: describeOutput.DomainStatus,
		}
	}
	return nil
}

// listDomains retrieves all OpenSearch domains in a region.
func listDomains(ctx context.Context, c *opensearch.Client) ([]types.DomainInfo, error) {
	input := &opensearch.ListDomainNamesInput{}

	output, err := c.ListDomainNames(ctx, input)
	if err != nil {
		return nil, err
	}

	return output.DomainNames, nil
}

// describeDomain fetches all details for a single domain.
func describeDomain(ctx context.Context, client *opensearch.Client, domain types.DomainInfo) *opensearch.DescribeDomainOutput {
	// Get detailed domain information
	describeInput := &opensearch.DescribeDomainInput{
		DomainName: domain.DomainName,
	}
	describeOutput, err := client.DescribeDomain(ctx, describeInput)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe OpenSearch domain", zap.String("name", *domain.DomainName), zap.Error(err))
		return nil
	}

	return describeOutput
}
