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

// opensearchAPI is the narrow subset of the opensearch client used by this
// collector, declared so the streaming helper can be exercised with a fake in
// tests. The signatures mirror the SDK exactly so the concrete
// *opensearch.Client satisfies it.
type opensearchAPI interface {
	ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomain(context.Context, *opensearch.DescribeDomainInput, ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error)
}

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

	return streamDomains(ctx, client, res)
}

// streamDomains lists every OpenSearch domain (ListDomainNames returns them all
// in one shot — this API has no pagination) and pushes each DomainDetail as its
// per-domain DescribeDomain call finishes; do not refactor into a
// build-slice-then-push pattern, as that would risk the 30s consumer idle
// timeout in core-sdk schema/platform.go (see commit 8295d1b). A domain whose
// DescribeDomain fails is skipped (describeDomain returns nil) so one failure
// neither panics nor aborts the rest of the region.
func streamDomains(ctx context.Context, client opensearchAPI, res chan<- any) error {
	domains, err := listDomains(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list OpenSearch domains", zap.Error(err))
		return err
	}

	for _, domain := range domains {
		describeOutput := describeDomain(ctx, client, domain)
		// describeDomain returns nil when DescribeDomain fails; skip rather
		// than dereference (a single failed domain must not panic and abort
		// the whole region's collection).
		if describeOutput == nil {
			continue
		}
		res <- DomainDetail{
			DomainStatus: describeOutput.DomainStatus,
		}
	}
	return nil
}

// listDomains retrieves all OpenSearch domains in a region.
func listDomains(ctx context.Context, c opensearchAPI) ([]types.DomainInfo, error) {
	input := &opensearch.ListDomainNamesInput{}

	output, err := c.ListDomainNames(ctx, input)
	if err != nil {
		return nil, err
	}

	return output.DomainNames, nil
}

// describeDomain fetches all details for a single domain.
func describeDomain(ctx context.Context, client opensearchAPI, domain types.DomainInfo) *opensearch.DescribeDomainOutput {
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
