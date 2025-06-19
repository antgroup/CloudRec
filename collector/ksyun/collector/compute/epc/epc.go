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

package epc

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	epc "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/epc/v20151101"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type KSyunEPCDetail struct {
	EPC any
}

func GetEPCResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.EPC,
		ResourceTypeName:  collector.EPC,
		ResourceGroupType: constant.COMPUTE,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/44/1003`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).EPC
			request := epc.NewDescribeEpcsRequest()
			request.MaxResults = common.IntPtr(100)
			count := 0

			for {
				responseStr := cli.DescribeEpcsWithContext(ctx, request)
				collector.ShowResponse(ctx, collector.EPC, "DescribeEpcs", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("EPC DescribeEpcs error", zap.Error(err))
					return err
				}

				response := epc.NewDescribeEpcsResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("EPC DescribeEpcsResponse decode error", zap.Error(err))
					return err
				}
				if len(response.HostSet) == 0 {
					break
				}

				for i := range response.HostSet {
					res <- &KSyunEPCDetail{
						EPC: &response.HostSet[i],
					}
				}
				count += len(response.HostSet)
				if response.NextToken == nil || count >= *response.TotalCount {
					break
				}

				request.NextToken = response.NextToken
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.EPC.HostId",
			ResourceName: "$.EPC.HostName",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"cn-central-1",    // 华中1（武汉）
			"ap-singapore-1",  // 新加坡
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-north-1-gov",  // 华北政务1（北京）
			"cn-southwest-1",  // 西南1（重庆）
			"cn-northwest-1",  // 西北1（庆阳）
			"cn-northwest-2",  // 西北2区（庆阳）
			"cn-northwest-3",  // 西北3区（宁夏）
			"cn-north-vip1",   // 华北专属1区（天津-小米）
			"cn-ningbo-1",     // 华东2（宁波）
			"cn-northwest-4",  // 西北4（海东）
			"cn-nanjing-1",    // 华东3（南京星云）
			"cn-ulanqab-1",    // 华北2（乌兰察布）
			"cn-northwest-5",  // 西北5（克拉玛依)
		},
		Dimension: schema.Regional,
	}
}
