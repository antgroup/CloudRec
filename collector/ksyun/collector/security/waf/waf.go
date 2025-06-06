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

package waf

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	waf "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/waf/v20200707"
	"go.uber.org/zap"
	"strings"
)

type DescribeDomainsResponse struct {
	RequestId           *string `json:"RequestId" name:"RequestId"`
	ResourceRecordInfos []struct {
		ResourceRecordId *string `json:"ResourceRecordId" name:"ResourceRecordId"`
	} `json:"ResourceRecordInfos" name:"ResourceRecordInfos"`
	Total int `json:"Total" name:"Total"`
}

type DescribeDomainsResponseAny struct {
	RequestId           *string `json:"RequestId" name:"RequestId"`
	ResourceRecordInfos []any   `json:"ResourceRecordInfos" name:"ResourceRecordInfos"`
	Total               int     `json:"Total" name:"Total"`
}

type DescribeRulesResponseAny struct {
	RequestId          *string `json:"RequestId" name:"RequestId"`
	AccessControlRules []any   `json:"AccessControlRules" name:"AccessControlRules"`
	Total              int     `json:"Total" name:"Total"`
}

type Detail struct {
	ResourceRecord     any
	AccessControlRules []any
}

func GetWAFResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.WAF,
		ResourceTypeName:  collector.WAF,
		ResourceGroupType: constant.SECURITY,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/0/1061`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).WAF

			describeWAF3Domains(ctx, cli, res)
			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.ResourceRecord.ResourceRecordId",
			ResourceName: "$.ResourceRecord.ResourceRecord",
		},
		Regions: []string{
			"cn-beijing-6", // 华北1（北京）
		},
		Dimension: schema.Global,
	}
}

func describeWAF3Domains(ctx context.Context, cli *waf.Client, res chan<- any) {
	request := waf.NewDescribeDomainsRequest()

	responseStr := cli.DescribeDomainsWithContext(ctx, request)
	collector.ShowResponse(ctx, "WAF", "DescribeDomains", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("WAF DescribeDomains error", zap.Error(err))
		return
	}

	localResponse := &DescribeDomainsResponse{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(localResponse)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("WAF DescribeDomains decode error", zap.Error(err))
		return
	}

	response := &DescribeDomainsResponseAny{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("WAF DescribeDomains decode error", zap.Error(err))
		return
	}

	if len(response.ResourceRecordInfos) == 0 || len(localResponse.ResourceRecordInfos) != len(response.ResourceRecordInfos) {
		return
	}

	for i := range response.ResourceRecordInfos {
		res <- Detail{
			ResourceRecord:     response.ResourceRecordInfos[i],
			AccessControlRules: describeAccessControlRules(ctx, cli, localResponse.ResourceRecordInfos[i].ResourceRecordId),
		}
	}
}

func describeAccessControlRules(ctx context.Context, cli *waf.Client, rrId *string) []any {
	request := waf.NewDescribeAccessControlRulesRequest()
	request.ResourceRecordId = rrId
	responseStr := cli.DescribeAccessControlRulesWithContext(ctx, request)
	collector.ShowResponse(ctx, "WAF", "DescribeAccessControlRules", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("WAF DescribeAccessControlRules error", zap.Error(err))
		return nil
	}

	response := &DescribeRulesResponseAny{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("WAF DescribeAccessControlRules decode error", zap.Error(err))
		return nil
	}

	return response.AccessControlRules
}
