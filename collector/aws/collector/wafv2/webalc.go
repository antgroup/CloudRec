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

package wafv2

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetWebACLResource returns a WebACL Resource
func GetWebACLResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.WebACL,
		ResourceTypeName:   "Web ACL",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://docs.aws.amazon.com/waf/latest/APIReference/API_ListWebACLs.html`,
		ResourceDetailFunc: GetWebACLDetail,
		RowField: schema.RowField{
			ResourceId:   "$.WebACL.Id",
			ResourceName: "$.WebACL.Name",
		},
		Dimension: schema.Global,
	}
}

type WebACLDetail struct {

	// The WebACL
	WebACL types.WebACL

	// [CLOUDFRONT, REGIONAL]
	Scope types.Scope
}

func GetWebACLDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).WAFv2
	webACLDetails, err := describeWebACLDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeWebACLDetails error", zap.Error(err))
		return err
	}
	for _, webACLDetail := range webACLDetails {
		res <- webACLDetail
	}

	return nil
}

func describeWebACLDetails(ctx context.Context, c *wafv2.Client) (webACLDetails []WebACLDetail, err error) {

	for _, scope := range types.Scope.Values("") {
		webACLSummaryList, err := listWebACLs(ctx, c, scope)
		if err != nil {
			log.CtxLogger(ctx).Warn("listWebACLs error", zap.Error(err))
			return nil, err
		}
		for _, webACLSummary := range webACLSummaryList {
			webACLDetails = append(webACLDetails, WebACLDetail{
				WebACL: getWebACL(ctx, c, webACLSummary.Id, webACLSummary.Name, scope),
				Scope:  scope,
			})
		}
	}

	return webACLDetails, nil
}

func getWebACL(ctx context.Context, c *wafv2.Client, id *string, name *string, scope types.Scope) types.WebACL {
	input := &wafv2.GetWebACLInput{
		Id:    id,
		Name:  name,
		Scope: scope,
	}
	output, err := c.GetWebACL(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("getWebACL error", zap.Error(err))
		return types.WebACL{}
	}

	return *output.WebACL
}

func listWebACLs(ctx context.Context, c *wafv2.Client, scope types.Scope) (webACLSummaryList []types.WebACLSummary, err error) {
	input := &wafv2.ListWebACLsInput{
		Scope: scope,
	}
	output, err := c.ListWebACLs(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("listWebACLs error", zap.Error(err))
		return nil, err
	}
	webACLSummaryList = append(webACLSummaryList, output.WebACLs...)
	for output.NextMarker != nil {
		input.NextMarker = output.NextMarker
		output, err = c.ListWebACLs(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("listWebACLs error", zap.Error(err))
			return nil, err
		}
		webACLSummaryList = append(webACLSummaryList, output.WebACLs...)
	}

	return webACLSummaryList, nil
}
