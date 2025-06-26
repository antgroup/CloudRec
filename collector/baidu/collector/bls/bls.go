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

package bls

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/bls"
	"github.com/baidubce/bce-sdk-go/services/bls/api"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	LogStoreId string
	LogStore   api.LogStore
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.BLS,
		ResourceTypeName:  collector.BLS,
		ResourceGroupType: constant.STORE,
		Desc:              `https://cloud.baidu.com/doc/BLS/s/Zkjtpa97z`,
		Regions: []string{
			"bls-log.bj.baidubce.com",
			"bls-log.gz.baidubce.com",
			"bls-log.su.baidubce.com",
			"bls-log.bd.baidubce.com",
			"bls-log.fwh.baidubce.com",
			"bls-log.yq.baidubce.com",
		},
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*collector.Services).BLSClient

			total := 0
			args := bls.ListLogStoreRequest{
				PageNo:   1,
				PageSize: 20,
			}
			for {
				response, err := client.ListLogStoreV2(args)
				if err != nil {
					log.CtxLogger(ctx).Warn("ListLogStoreV2 error", zap.Error(err))
					return err
				}
				for _, logStore := range response.Result {
					d := Detail{
						// 百度云限制同一区域内的logstore名称不可以相同，防止不同区域存在同名的logstore
						LogStoreId: logStore.LogStoreName + "-" + client.Config.Region,
						LogStore:   logStore,
					}
					total++
					res <- d
				}
				if total >= response.TotalCount {
					break
				}
				args.PageNo++
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.LogStoreId",
			ResourceName: "$.LogStore.logStoreName",
		},
		Dimension: schema.Regional,
	}
}
