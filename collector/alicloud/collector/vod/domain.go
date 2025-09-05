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

package vod

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vod"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetVODDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.VODDomain,
		ResourceTypeName:   collector.VODDomain,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/VOD`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Domains.DomainName",
			ResourceName: "$.Domains.DomainName",
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
	cli := service.(*collector.Services).VOD
	req := vod.CreateDescribeVodUserDomainsRequest()
	req.Scheme = "https"

	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		response, err := cli.DescribeVodUserDomains(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeVodUserDomains error", zap.Error(err))
			return err
		}
		for _, i := range response.Domains.PageData {
			d := &Detail{
				Domains:         i,
				DomainDetail:    describeVodDomainDetail(ctx, cli, i.DomainName),
				DomainConfigs:   describeVodDomainConfigs(ctx, cli, i.DomainName),
				CertificateList: describeVodCertificateList(ctx, cli, i.DomainName),
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
	Domains         vod.PageData
	DomainDetail    vod.DomainDetail
	DomainConfigs   []vod.DomainConfig
	CertificateList vod.CertificateListModel
}

func describeVodDomainDetail(ctx context.Context, cli *vod.Client, domainName string) vod.DomainDetail {
	request := vod.CreateDescribeVodDomainDetailRequest()
	request.Scheme = "https"
	request.DomainName = domainName

	response, err := cli.DescribeVodDomainDetail(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeVodDomainDetail error", zap.String("domain", domainName), zap.Error(err))
		return vod.DomainDetail{}
	}
	return response.DomainDetail
}

func describeVodDomainConfigs(ctx context.Context, cli *vod.Client, domainName string) []vod.DomainConfig {
	request := vod.CreateDescribeVodDomainConfigsRequest()
	request.Scheme = "https"
	request.DomainName = domainName

	response, err := cli.DescribeVodDomainConfigs(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeVodDomainConfigs error", zap.String("domain", domainName), zap.Error(err))
		return []vod.DomainConfig{}
	}
	return response.DomainConfigs.DomainConfig
}

func describeVodCertificateList(ctx context.Context, cli *vod.Client, domainName string) vod.CertificateListModel {
	request := vod.CreateDescribeVodCertificateListRequest()
	request.Scheme = "https"
	request.DomainName = domainName

	response, err := cli.DescribeVodCertificateList(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeVodCertificateList error", zap.String("domain", domainName), zap.Error(err))
		return vod.CertificateListModel{}
	}
	return response.CertificateListModel
}
