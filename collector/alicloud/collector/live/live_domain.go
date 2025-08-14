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

package live

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/live"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetLiveDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.LiveDomain,
		ResourceTypeName:   "Live Domain",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/live`,
		ResourceDetailFunc: GetLiveDomainDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DomainName",
			ResourceName: "$.DomainName",
		},
		Dimension: schema.Global,
	}
}

type LiveDomainDetail struct {
	Domain          live.PageData
	DomainDetail    live.DomainDetail
	DomainConfigs   live.DomainConfigsInDescribeLiveDomainConfigs
	CertificateInfo live.CertInfosInDescribeLiveDomainCertificateInfo
	DomainMapping   live.LiveDomainModels
}

func GetLiveDomainDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Live

	describeUserDomainsRequest := live.CreateDescribeLiveUserDomainsRequest()
	describeUserDomainsRequest.Scheme = "https"
	describeUserDomainsRequest.PageSize = requests.NewInteger(100)
	describeUserDomainsRequest.PageNumber = requests.NewInteger(1)

	for {
		response, err := cli.DescribeLiveUserDomains(describeUserDomainsRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeLiveUserDomains error", zap.Error(err))
			return err
		}

		if len(response.Domains.PageData) == 0 {
			break
		}

		for _, domain := range response.Domains.PageData {
			domainDetail := getLiveDomainDetail(ctx, cli, domain.DomainName)
			domainConfigs := getLiveDomainConfigs(ctx, cli, domain.DomainName)
			certificateInfo := getLiveDomainCertificateInfo(ctx, cli, domain.DomainName)
			domainMapping := getLiveDomainMapping(ctx, cli, domain.DomainName)

			d := LiveDomainDetail{
				Domain:          domain,
				DomainDetail:    domainDetail,
				DomainConfigs:   domainConfigs,
				CertificateInfo: certificateInfo,
				DomainMapping:   domainMapping,
			}

			res <- d
		}

		// Check if there are more pages
		totalCount := response.TotalCount
		pageSize := describeUserDomainsRequest.PageSize
		pageNumber := describeUserDomainsRequest.PageNumber

		pageNum, _ := pageNumber.GetValue()
		pageSizeNum, _ := pageSize.GetValue()
		totalNum := totalCount

		if pageNum*pageSizeNum >= int(totalNum) {
			break
		}

		describeUserDomainsRequest.PageNumber = requests.NewInteger(pageNum + 1)
	}

	return nil
}

func getLiveDomainDetail(ctx context.Context, cli *live.Client, domainName string) live.DomainDetail {
	describeLiveDomainDetailRequest := live.CreateDescribeLiveDomainDetailRequest()
	describeLiveDomainDetailRequest.Scheme = "https"
	describeLiveDomainDetailRequest.DomainName = domainName

	response, err := cli.DescribeLiveDomainDetail(describeLiveDomainDetailRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLiveDomainDetail error", zap.Error(err), zap.String("domainName", domainName))
		return live.DomainDetail{}
	}

	return response.DomainDetail
}

func getLiveDomainConfigs(ctx context.Context, cli *live.Client, domainName string) live.DomainConfigsInDescribeLiveDomainConfigs {
	describeLiveDomainConfigsRequest := live.CreateDescribeLiveDomainConfigsRequest()
	describeLiveDomainConfigsRequest.Scheme = "https"
	describeLiveDomainConfigsRequest.DomainName = domainName

	response, err := cli.DescribeLiveDomainConfigs(describeLiveDomainConfigsRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLiveDomainConfigs error", zap.Error(err), zap.String("domainName", domainName))
		return live.DomainConfigsInDescribeLiveDomainConfigs{}
	}

	return response.DomainConfigs
}

func getLiveDomainCertificateInfo(ctx context.Context, cli *live.Client, domainName string) live.CertInfosInDescribeLiveDomainCertificateInfo {
	describeCertificateInfoRequest := live.CreateDescribeLiveDomainCertificateInfoRequest()
	describeCertificateInfoRequest.Scheme = "https"
	describeCertificateInfoRequest.DomainName = domainName

	response, err := cli.DescribeLiveDomainCertificateInfo(describeCertificateInfoRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLiveDomainCertificateInfo error", zap.Error(err), zap.String("domainName", domainName))
		return live.CertInfosInDescribeLiveDomainCertificateInfo{}
	}

	return response.CertInfos
}

func getLiveDomainMapping(ctx context.Context, cli *live.Client, domainName string) live.LiveDomainModels {
	describeDomainMappingRequest := live.CreateDescribeLiveDomainMappingRequest()
	describeDomainMappingRequest.Scheme = "https"
	describeDomainMappingRequest.DomainName = domainName

	response, err := cli.DescribeLiveDomainMapping(describeDomainMappingRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLiveDomainMapping error", zap.Error(err), zap.String("domainName", domainName))
		return live.LiveDomainModels{}
	}

	return response.LiveDomainModels
}
