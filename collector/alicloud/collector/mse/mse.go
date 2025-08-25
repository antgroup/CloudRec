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

package mse

import (
	"context"
	mse20190531 "github.com/alibabacloud-go/mse-20190531/v5/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetMSEResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MSE,
		ResourceTypeName:   "MSE",
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               "https://api.aliyun.com/product/mse",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Gateway.GatewayUniqueId",
			ResourceName: "$.Gateway.Name",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-fuzhou",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"cn-wuhan-lr",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-zhengzhou-jva",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).MSE

	listGatewayRequest := &mse20190531.ListGatewayRequest{}
	runtime := &util.RuntimeOptions{}
	gateways, err := cli.ListGatewayWithOptions(listGatewayRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("ListGatewayWithOptions error", zap.Error(err))
		return err
	}

	for _, gateway := range gateways.Body.Data.Result {
		res <- Detail{
			RegionId:          *cli.RegionId,
			Gateway:           gateway,
			GatewaySlb:        describeGatewaySlb(ctx, cli, *gateway.GatewayUniqueId),
			SecurityGroupRule: describeSecurityGroupRule(ctx, cli, *gateway.GatewayUniqueId),
			Domain:            describeGatewayDomain(ctx, cli, *gateway.GatewayUniqueId),
			Auth:              describeGatewayAuth(ctx, cli, *gateway.GatewayUniqueId),
		}
	}

	return nil

}

type Detail struct {
	// region
	RegionId string

	// Gateway information
	Gateway *mse20190531.ListGatewayResponseBodyDataResult

	// Gateway SLB information
	GatewaySlb []*mse20190531.ListGatewaySlbResponseBodyData

	// Security group information
	SecurityGroupRule []*mse20190531.ListSecurityGroupRuleResponseBodyData

	// Domain name associated with the gateway
	Domain []*mse20190531.ListGatewayDomainResponseBodyData

	// Gateway authentication information
	Auth *mse20190531.GetGatewayAuthDetailResponseBodyData
}

// Query the SLB information of the gateway ingress instance
func describeGatewaySlb(ctx context.Context, cli *mse20190531.Client, gatewayUniqueId string) []*mse20190531.ListGatewaySlbResponseBodyData {
	listGatewaySlbRequest := &mse20190531.ListGatewaySlbRequest{
		GatewayUniqueId: tea.String(gatewayUniqueId),
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListGatewaySlbWithOptions(listGatewaySlbRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListGatewaySlbWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Data
}

// Query the information about the gateway security group
func describeSecurityGroupRule(ctx context.Context, cli *mse20190531.Client, gatewayUniqueId string) []*mse20190531.ListSecurityGroupRuleResponseBodyData {
	listSecurityGroupRuleRequest := &mse20190531.ListSecurityGroupRuleRequest{
		GatewayUniqueId: tea.String(gatewayUniqueId),
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListSecurityGroupRuleWithOptions(listSecurityGroupRuleRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListSecurityGroupRuleWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Data
}

// Query the list of domain names associated with the gateway
func describeGatewayDomain(ctx context.Context, cli *mse20190531.Client, gatewayUniqueId string) []*mse20190531.ListGatewayDomainResponseBodyData {
	listGatewayDomainRequest := &mse20190531.ListGatewayDomainRequest{
		GatewayUniqueId: tea.String(gatewayUniqueId),
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.ListGatewayDomainWithOptions(listGatewayDomainRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListGatewayDomainWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Data
}

// Obtain gateway authentication information
func describeGatewayAuth(ctx context.Context, cli *mse20190531.Client, gatewayUniqueId string) *mse20190531.GetGatewayAuthDetailResponseBodyData {
	getGatewayAuthDetailRequest := &mse20190531.GetGatewayAuthDetailRequest{
		GatewayUniqueId: tea.String(gatewayUniqueId),
	}
	runtime := &util.RuntimeOptions{}

	result, err := cli.GetGatewayAuthDetailWithOptions(getGatewayAuthDetailRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetGatewayAuthDetailWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Data
}
