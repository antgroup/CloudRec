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
	"fmt"
	alidns20150109 "github.com/alibabacloud-go/alidns-20150109/v4/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetDNSResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DNS,
		ResourceTypeName:   "DNS",
		ResourceGroupType:  constant.NET,
		Desc:               "https://api.aliyun.com/product/Alidns",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ResourceId",
			ResourceName: "$.ResourceName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
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
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.DNS
	describeDnsProductInstancesRequest := &alidns20150109.DescribeDnsProductInstancesRequest{}
	runtime := &util.RuntimeOptions{
		ConnectTimeout: tea.Int(10000),
		ReadTimeout:    tea.Int(10000),
	}
	dnsInstances, err := cli.DescribeDnsProductInstancesWithOptions(describeDnsProductInstancesRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDnsProductInstancesWithOptions error", zap.Error(err))
		return err
	}

	gmtInfo := describeGtmInstance(ctx, cli)
	domain := describeDomain(ctx, cli)

	if len(dnsInstances.Body.DnsProducts.DnsProduct) == 0 && len(domain) == 0 && len(gmtInfo) == 0 {
		return nil
	}

	d := Detail{
		ResourceId:     fmt.Sprintf("%s_%s", tea.StringValue(cli.RegionId), services.CloudAccountId),
		ResourceName:   fmt.Sprintf("DNS_%s_%s", tea.StringValue(cli.RegionId), services.CloudAccountId),
		DnsProduct:     dnsInstances.Body.DnsProducts,
		Domain:         domain,
		Gmt:            gmtInfo,
		AccessStrategy: describeDnsGtmAccessStrategy(ctx, cli, gmtInfo),
	}

	res <- d

	return nil
}

type Detail struct {
	ResourceId   string
	ResourceName string
	// Cloud DNS instance information
	DnsProduct *alidns20150109.DescribeDnsProductInstancesResponseBodyDnsProducts

	// Domain information
	Domain []*alidns20150109.DescribeDomainInfoResponseBody

	// GTM Information
	Gmt []*alidns20150109.DescribeDnsGtmInstancesResponseBodyGtmInstances

	// Access policy information
	AccessStrategy []*alidns20150109.DescribeDnsGtmAccessStrategiesResponseBodyStrategies
}

// Get domain name information
func describeDomain(ctx context.Context, cli *alidns20150109.Client) []*alidns20150109.DescribeDomainInfoResponseBody {
	describeDomainsRequest := &alidns20150109.DescribeDomainsRequest{}
	runtime := &util.RuntimeOptions{}

	domains, err := cli.DescribeDomainsWithOptions(describeDomainsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDomainsWithOptions error", zap.Error(err))
		return nil
	}

	// Get domain details
	var domainInfo []*alidns20150109.DescribeDomainInfoResponseBody
	for _, domain := range domains.Body.Domains.Domain {
		describeDomainInfoRequest := &alidns20150109.DescribeDomainInfoRequest{
			DomainName: tea.String(*domain.DomainName),
		}

		result, err := cli.DescribeDomainInfoWithOptions(describeDomainInfoRequest, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDomainInfoWithOptions error", zap.Error(err))
			return nil
		}

		domainInfo = append(domainInfo, result.Body)
	}

	return domainInfo
}

func describeGtmInstance(ctx context.Context, cli *alidns20150109.Client) []*alidns20150109.DescribeDnsGtmInstancesResponseBodyGtmInstances {
	describeDnsGtmInstancesRequest := &alidns20150109.DescribeDnsGtmInstancesRequest{}
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeDnsGtmInstancesWithOptions(describeDnsGtmInstancesRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeDnsGtmInstancesWithOptions error", zap.Error(err))
		return nil
	}

	return result.Body.GtmInstances
}

// Get instance access policy information
func describeDnsGtmAccessStrategy(ctx context.Context, cli *alidns20150109.Client, gmtInfo []*alidns20150109.DescribeDnsGtmInstancesResponseBodyGtmInstances) []*alidns20150109.DescribeDnsGtmAccessStrategiesResponseBodyStrategies {
	var strategies []*alidns20150109.DescribeDnsGtmAccessStrategiesResponseBodyStrategies

	for _, instance := range gmtInfo {
		describeDnsGtmAccessStrategiesRequest := &alidns20150109.DescribeDnsGtmAccessStrategiesRequest{
			InstanceId:   tea.String(*instance.InstanceId),
			StrategyMode: tea.String(*instance.Config.StrategyMode),
		}
		runtime := &util.RuntimeOptions{}

		result, err := cli.DescribeDnsGtmAccessStrategiesWithOptions(describeDnsGtmAccessStrategiesRequest, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDnsGtmAccessStrategiesWithOptions error", zap.Error(err))
			return nil
		}
		strategies = append(strategies, result.Body.Strategies)
	}
	return strategies
}
