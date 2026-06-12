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
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

type WebACLDetail struct {

	// The WebACL
	WebACL types.WebACL

	// [CLOUDFRONT, REGIONAL]
	Scope types.Scope
}

// GetWebACLDetail streams each Web ACL as the per-scope ListWebACLs
// pagination yields it and its GetWebACL call completes, iterating over
// both CLOUDFRONT and REGIONAL scopes. Streaming avoids the 30s consumer
// idle timeout in core-sdk schema/platform.go when an account has many
// Web ACLs.
func GetWebACLDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).WAFv2

	for _, scope := range types.Scope.Values("") {
		input := &wafv2.ListWebACLsInput{
			Scope: scope,
		}
		for {
			output, err := client.ListWebACLs(ctx, input)
			if err != nil {
				log.CtxLogger(ctx).Warn("listWebACLs error", zap.Error(err), zap.String("scope", string(scope)))
				break
			}
			for _, webACLSummary := range output.WebACLs {
				res <- WebACLDetail{
					WebACL: getWebACL(ctx, client, webACLSummary.Id, webACLSummary.Name, scope),
					Scope:  scope,
				}
			}
			if output.NextMarker == nil {
				break
			}
			input.NextMarker = output.NextMarker
		}
	}

	return nil
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
