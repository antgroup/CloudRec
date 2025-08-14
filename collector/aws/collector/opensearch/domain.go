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
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const maxWorkers = 10

// GetDomainResource returns AWS OpenSearch domain resource definition
func GetDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.OpenSearch,
		ResourceTypeName:   "OpenSearch Domain",
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainStatus.html",
		ResourceDetailFunc: GetDomainDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Domain.DomainId",
			ResourceName: "$.Domain.DomainName",
		},
		Dimension: schema.Regional,
	}
}

// DomainDetail aggregates all information for a single OpenSearch domain.
type DomainDetail struct {
	Domain *opensearch.DescribeDomainOutput
}

// GetDomainDetail fetches the details for all OpenSearch domains in a region.
func GetDomainDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).OpenSearch

	domains, err := listDomains(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list OpenSearch domains", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.DomainInfo, len(domains))

	// Start worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range tasks {
				detail := describeDomainDetail(ctx, client, domain)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks
	for _, domain := range domains {
		tasks <- domain
	}
	close(tasks)

	wg.Wait()
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

// describeDomainDetail fetches all details for a single domain.
func describeDomainDetail(ctx context.Context, client *opensearch.Client, domain types.DomainInfo) *DomainDetail {
	// Get detailed domain information
	describeInput := &opensearch.DescribeDomainInput{
		DomainName: domain.DomainName,
	}
	describeOutput, err := client.DescribeDomain(ctx, describeInput)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe OpenSearch domain", zap.String("name", *domain.DomainName), zap.Error(err))
		return nil
	}

	return &DomainDetail{
		Domain: describeOutput,
	}
}
