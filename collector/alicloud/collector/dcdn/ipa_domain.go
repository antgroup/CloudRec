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

package dcdn

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dcdn"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetDCDNIpaDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DCDNIpaDomain,
		ResourceTypeName:   "DCDN IpaDomain",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/dcdn`,
		ResourceDetailFunc: GetDCDNIpaDomainDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DomainId",
			ResourceName: "$.DomainName",
		},
		Dimension: schema.Global,
	}
}

type DCDNIpaDomainDetail struct {
	Domain          dcdn.PageData
	DomainDetail    dcdn.DomainDetail
	DomainConfigs   dcdn.DomainConfigsInDescribeDcdnIpaDomainConfigs
	CertificateInfo dcdn.CertInfosInDescribeDcdnDomainCertificateInfo
}

func GetDCDNIpaDomainDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).DCDN

	describeIpaUserDomainsRequest := dcdn.CreateDescribeDcdnIpaUserDomainsRequest()
	describeIpaUserDomainsRequest.Scheme = "https"
	describeIpaUserDomainsRequest.PageSize = requests.NewInteger(100)
	describeIpaUserDomainsRequest.PageNumber = requests.NewInteger(1)

	for {
		response, err := cli.DescribeDcdnIpaUserDomains(describeIpaUserDomainsRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDcdnIpaUserDomains error", zap.Error(err))
			return err
		}

		if len(response.Domains.PageData) == 0 {
			break
		}

		for _, domain := range response.Domains.PageData {
			domainDetail := getIpaDomainDetail(ctx, cli, domain.DomainName)
			domainConfigs := getIpaDomainConfigs(ctx, cli, domain.DomainName)
			certificateInfo := getDomainCertificateInfo(ctx, cli, domain.DomainName)

			d := DCDNIpaDomainDetail{
				Domain:          domain,
				DomainDetail:    domainDetail,
				DomainConfigs:   domainConfigs,
				CertificateInfo: certificateInfo,
			}

			res <- d
		}

		// Check if there are more pages
		totalCount := response.TotalCount
		pageSize := describeIpaUserDomainsRequest.PageSize
		pageNumber := describeIpaUserDomainsRequest.PageNumber

		pageNum, _ := pageNumber.GetValue()
		pageSizeNum, _ := pageSize.GetValue()
		totalNum := totalCount

		if pageNum*pageSizeNum >= int(totalNum) {
			break
		}

		describeIpaUserDomainsRequest.PageNumber = requests.NewInteger(pageNum + 1)
	}

	return nil
}

func getIpaDomainDetail(ctx context.Context, cli *dcdn.Client, domainName string) dcdn.DomainDetail {
	describeIpaDomainDetailRequest := dcdn.CreateDescribeDcdnIpaDomainDetailRequest()
	describeIpaDomainDetailRequest.Scheme = "https"
	describeIpaDomainDetailRequest.DomainName = domainName

	response, err := cli.DescribeDcdnIpaDomainDetail(describeIpaDomainDetailRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDcdnIpaDomainDetail error", zap.Error(err), zap.String("domainName", domainName))
		return dcdn.DomainDetail{}
	}

	return response.DomainDetail
}

func getIpaDomainConfigs(ctx context.Context, cli *dcdn.Client, domainName string) dcdn.DomainConfigsInDescribeDcdnIpaDomainConfigs {
	describeIpaDomainConfigsRequest := dcdn.CreateDescribeDcdnIpaDomainConfigsRequest()
	describeIpaDomainConfigsRequest.Scheme = "https"
	describeIpaDomainConfigsRequest.DomainName = domainName

	response, err := cli.DescribeDcdnIpaDomainConfigs(describeIpaDomainConfigsRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDcdnIpaDomainConfigs error", zap.Error(err), zap.String("domainName", domainName))
		return dcdn.DomainConfigsInDescribeDcdnIpaDomainConfigs{}
	}

	return response.DomainConfigs
}

func getDomainCertificateInfo(ctx context.Context, cli *dcdn.Client, domainName string) dcdn.CertInfosInDescribeDcdnDomainCertificateInfo {
	describeCertificateInfoRequest := dcdn.CreateDescribeDcdnDomainCertificateInfoRequest()
	describeCertificateInfoRequest.Scheme = "https"
	describeCertificateInfoRequest.DomainName = domainName

	response, err := cli.DescribeDcdnDomainCertificateInfo(describeCertificateInfoRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDcdnDomainCertificateInfo error", zap.Error(err), zap.String("domainName", domainName))
		return dcdn.CertInfosInDescribeDcdnDomainCertificateInfo{}
	}

	return response.CertInfos
}
