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

package kec

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kec "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kec/v20160304"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type DescribeInstancesResponse struct {
	Marker        *int    `json:"Marker" name:"Marker"`
	InstanceCount *int    `json:"InstanceCount" name:"InstanceCount"`
	RequestId     *string `json:"RequestId" name:"RequestId"`
	InstancesSet  []any   `json:"InstancesSet" name:"InstancesSet"`
}

type KSyunKECInstanceDetail struct {
	Instance any
}

func GetKECResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KEC,
		ResourceTypeName:  collector.KEC,
		ResourceGroupType: constant.COMPUTE,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/69/1001`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KEC
			request := kec.NewDescribeInstancesRequest()
			request.MaxResults = common.IntPtr(100)
			request.Marker = common.IntPtr(0)
			count := 0

			for {
				responseStr := cli.DescribeInstancesWithContext(ctx, request)
				collector.ShowResponse(ctx, collector.KEC, "DescribeInstances", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KEC DescribeInstances error", zap.Error(err))
					return err
				}

				response := &DescribeInstancesResponse{}
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KEC DescribeInstancesResponse decode error", zap.Error(err))
					return err
				}
				if len(response.InstancesSet) == 0 {
					break
				}

				for i := range response.InstancesSet {
					res <- &KSyunKECInstanceDetail{
						Instance: response.InstancesSet[i],
					}
				}

				count += len(response.InstancesSet)
				if count >= *response.InstanceCount {
					break
				}
				request.Marker = response.Marker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-hongkong-2",   // 香港
			"ap-singapore-1",  // 新加坡
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-beijing-fin",  // 华北金融1（北京）
			"cn-north-1-gov",  // 华北政务1（北京）
			"cn-northwest-2",  // 西北2区（庆阳）
			"cn-ningbo-1",     // 华东2（宁波）
			"cn-qingdao-1",    // 自用（青岛）
		},
		Dimension: schema.Regional,
	}
}
