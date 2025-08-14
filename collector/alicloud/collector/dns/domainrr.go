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

package dns

import (
	"context"
	alidns20150109 "github.com/alibabacloud-go/alidns-20150109/v4/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetDomainRRResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DomainRR,
		ResourceTypeName:   "DomainRR",
		ResourceGroupType:  constant.NET,
		Desc:               "https://api.aliyun.com/product/Alidns",
		ResourceDetailFunc: GetDomainRRDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DomainInfo.DomainId",
			ResourceName: "$.DomainInfo.DomainName",
		},
		Dimension: schema.Global,
	}
}

type DomainDetail struct {
	DomainInfo *alidns20150109.DescribeDomainsResponseBodyDomainsDomain

	ResourceRecords []*alidns20150109.DescribeDomainRecordsResponseBodyDomainRecordsRecord
}

func GetDomainRRDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.DNS

	domains, err := describeDomains(ctx, cli)

	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDomains error", zap.Error(err))
		return err
	}
	for _, domain := range domains {
		res <- DomainDetail{
			DomainInfo:      domain,
			ResourceRecords: getResourceRecords(ctx, cli, domain.DomainName),
		}
	}

	return nil
}

func getResourceRecords(ctx context.Context, cli *alidns20150109.Client, domainName *string) (resourceRecords []*alidns20150109.DescribeDomainRecordsResponseBodyDomainRecordsRecord) {
	req := alidns20150109.DescribeDomainRecordsRequest{DomainName: domainName}

	resp, err := cli.DescribeDomainRecords(&req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDomainRecords error", zap.Error(err))
		return nil
	}
	resourceRecords = append(resourceRecords, resp.Body.DomainRecords.Record...)
	for *resp.Body.PageNumber**resp.Body.PageSize < *resp.Body.TotalCount {
		req.PageNumber = increInt64Ptr(resp.Body.PageNumber)
		resp, err = cli.DescribeDomainRecords(&req)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDomainRecords error", zap.Error(err))
			return nil
		}
		resourceRecords = append(resourceRecords, resp.Body.DomainRecords.Record...)
	}

	return resourceRecords
}

func increInt64Ptr(number *int64) *int64 {
	*number += 1
	return number
}

func describeDomains(ctx context.Context, cli *alidns20150109.Client) (domains []*alidns20150109.DescribeDomainsResponseBodyDomainsDomain, err error) {
	describeDomainsRequest := &alidns20150109.DescribeDomainsRequest{}

	resp, err := cli.DescribeDomains(describeDomainsRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDomains error", zap.Error(err))
		return nil, err
	}
	domains = append(domains, resp.Body.Domains.Domain...)
	for *resp.Body.PageNumber**resp.Body.PageSize < *resp.Body.TotalCount {
		describeDomainsRequest.PageNumber = increInt64Ptr(resp.Body.PageNumber)
		resp, err = cli.DescribeDomains(describeDomainsRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDomains error", zap.Error(err))
			return nil, err
		}
		domains = append(domains, resp.Body.Domains.Domain...)
	}

	return domains, nil
}
