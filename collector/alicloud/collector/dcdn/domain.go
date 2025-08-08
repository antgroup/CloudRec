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

func GetDCDNDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DCDNDomain,
		ResourceTypeName:   collector.DCDNDomain,
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/dcdn`,
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
	cli := service.(*collector.Services).DCDN
	req := dcdn.CreateDescribeDcdnUserDomainsRequest()
	req.Scheme = "https"

	req.PageSize = requests.NewInteger(50)
	req.PageNumber = requests.NewInteger(1)
	count := 0
	for {
		response, err := cli.DescribeDcdnUserDomains(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeDcdnUserDomains error", zap.Error(err))
			return err
		}
		for _, i := range response.Domains.PageData {
			d := &Detail{
				Domains:       i,
				DomainConfigs: describeDcdnDomainConfigs(ctx, cli, i.DomainName),
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
	Domains dcdn.PageData

	DomainConfigs []dcdn.DomainConfig
}

func describeDcdnDomainConfigs(ctx context.Context, cli *dcdn.Client, domain string) (DomainConfigs []dcdn.DomainConfig) {
	request := dcdn.CreateDescribeDcdnDomainConfigsRequest()
	request.DomainName = domain
	request.Scheme = "https"
	response, err := cli.DescribeDcdnDomainConfigs(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDcdnDomainConfigs failed", zap.Error(err))
		return
	}

	return response.DomainConfigs.DomainConfig
}
