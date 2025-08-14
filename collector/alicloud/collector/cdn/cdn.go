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

package cdn

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cdn"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetCDNDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CDN,
		ResourceTypeName:   collector.CDN,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Cdn`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.UserDomains.DomainName",
			ResourceName: "$.UserDomains.DomainName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"ap-southeast-3",
			"ap-northeast-1",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CDN
	req := cdn.CreateDescribeUserDomainsRequest()
	req.Scheme = "https"

	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		response, err := cli.DescribeUserDomains(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeUserDomains error", zap.Error(err))
			return err
		}
		for _, i := range response.Domains.PageData {
			d := &Detail{
				UserDomains:       i,
				DomainConfig:      describeCdnDomainConfigs(ctx, cli, i.DomainName),
				CdnDeletedDomains: describeCdnDeletedDomains(ctx, cli, i.DomainName),
			}
			res <- d
		}
		count += len(response.Domains.PageData)
		if int64(count) >= response.TotalCount {
			break
		}

		req.PageNumber = requests.NewInteger(int(response.PageNumber) + 1)
	}

	return nil
}

type Detail struct {
	UserDomains cdn.PageData

	DomainConfig []cdn.DomainConfigInDescribeCdnDomainConfigs

	CdnDeletedDomains []cdn.PageData
}

func describeCdnDomainConfigs(ctx context.Context, cli *cdn.Client, domain string) (DomainConfig []cdn.DomainConfigInDescribeCdnDomainConfigs) {
	request := cdn.CreateDescribeCdnDomainConfigsRequest()
	request.DomainName = domain
	request.Scheme = "https"
	response, err := cli.DescribeCdnDomainConfigs(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeCdnDomainConfigs failed", zap.Error(err))
		return
	}

	return response.DomainConfigs.DomainConfig
}

func describeCdnDeletedDomains(ctx context.Context, cli *cdn.Client, domain string) (PageData []cdn.PageData) {
	request := cdn.CreateDescribeCdnDeletedDomainsRequest()
	request.Domain = domain
	request.Scheme = "https"
	response, err := cli.DescribeCdnDeletedDomains(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeCdnDeletedDomains failed", zap.Error(err))
		return
	}

	return response.Domains.PageData
}
