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

package kfs

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

type Detail struct {
	KFS any
}

func GetKFSResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KFS,
		ResourceTypeName:  collector.KFS,
		ResourceGroupType: constant.STORE,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/0/1035`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KEC
			request := kec.NewDescribeFileSystemsRequest()
			request.MaxResults = common.IntPtr(100)
			count := 0

			for {
				responseStr := cli.DescribeFileSystemsWithContext(ctx, request)
				collector.ShowResponse(ctx, "KFS", "DescribeFileSystems", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KFS DescribeFileSystems error", zap.Error(err))
					return err
				}

				response := kec.NewDescribeFileSystemsResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KFS DescribeFileSystems decode error", zap.Error(err))
					return err
				}
				if len(response.FileSystems) == 0 {
					break
				}

				for i := range response.FileSystems {
					res <- Detail{
						KFS: &response.FileSystems[i],
					}
				}
				count += len(response.FileSystems)
				if count >= *response.FileSystemCount {
					break
				}
				request.Marker = response.Marker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.KFS.FileSystemId",
			ResourceName: "$.KFS.FileSystemName",
		},
		Regions: []string{
			"cn-beijing-6",   // 华北1（北京）
			"cn-guangzhou-1", // 华南1（广州）
		},
		Dimension: schema.Regional,
	}
}
