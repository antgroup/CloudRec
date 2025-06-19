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

package nat

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	vpc "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/vpc/v20160304"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type Detail struct {
	NAT any
}

func GetNATResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.NAT,
		ResourceTypeName:  collector.NAT,
		ResourceGroupType: constant.NET,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/91/1129`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).VPC
			request := vpc.NewDescribeNatsRequest()
			request.MaxResults = common.IntPtr(100)

			for {
				responseStr := cli.DescribeNatsWithContext(ctx, request)
				collector.ShowResponse(ctx, "NAT", "DescribeNats", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("NAT DescribeNats error", zap.Error(err))
					return err
				}

				response := vpc.NewDescribeNatsResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("NAT DescribeNatsResponse decode error", zap.Error(err))
					return err
				}
				if len(response.NatSet) == 0 {
					break
				}

				for i := range response.NatSet {
					res <- &Detail{
						NAT: &response.NatSet[i],
					}
				}
				if response.NextToken == nil || len(response.NatSet) < *request.MaxResults {
					break
				}
				request.NextToken = response.NextToken
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.NAT.NatId",
			ResourceName: "$.NAT.NatName",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"cn-central-1",    // 华中1（武汉）
			"cn-hongkong-2",   // 香港
			"ap-singapore-1",  // 新加坡
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-beijing-fin",  // 华北金融1（北京）
			"cn-southwest-1",  // 西南1（重庆）
			"cn-northwest-1",  // 西北1（庆阳）
			"cn-northwest-2",  // 西北2区（庆阳）
			"cn-northwest-3",  // 西北3区（宁夏）
			"cn-north-vip1",   // 华北专属1区（天津-小米）
			"cn-ningbo-1",     // 华东2（宁波）
			"cn-northwest-4",  // 西北4（海东）
		},
		Dimension: schema.Regional,
	}
}
