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

package klog

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	klog "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/klog/v20200731"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type Detail struct {
	Pool any
}

func GetKLOGResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KLOG,
		ResourceTypeName:  collector.KLOG,
		ResourceGroupType: constant.LOG,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/92/1015`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KLOG
			request := klog.NewListProjectsRequest()
			count := 0
			size := 100
			request.Size = common.IntPtr(size)
			request.Page = common.IntPtr(1)

			for {
				responseStr := cli.ListProjectsWithContext(ctx, request)
				collector.ShowResponse(ctx, "KLOG", "ListProjects", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KLOG ListProjects error", zap.Error(err))
					return err
				}

				response := klog.NewListProjectsResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("EIP DescribeAddressesResponse decode error", zap.Error(err))
					return err
				}
				if len(response.Projects) == 0 {
					break
				}

				for i := range response.Projects {
					err = listLogPools(ctx, cli, response.Projects[i].ProjectName, res)
					if err != nil {
						continue
					}
				}
				count += len(response.Projects)
				if count >= *response.Total || len(response.Projects) < size {
					break
				}
				request.Page = common.IntPtr(*request.Page + 1)
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Pool.LogPoolId",
			ResourceName: "$.Pool.LogPoolName",
		},
		Regions: []string{
			"cn-beijing-6",   // 华北1（北京）
			"cn-guangzhou-1", // 华南1（广州）
		},
		Dimension: schema.Regional,
	}
}

func listLogPools(ctx context.Context, cli *klog.Client, projectName *string, res chan<- any) error {
	request := klog.NewListLogPoolsRequest()
	count := 0
	size := 100
	request.ProjectName = projectName
	request.Size = common.IntPtr(size)
	request.Page = common.IntPtr(1)

	for {
		responseStr := cli.ListLogPoolsWithContext(ctx, request)
		collector.ShowResponse(ctx, "KLOG", "ListLogPools", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KLOG ListLogPools error", zap.Error(err))
			return err
		}

		response := klog.NewListLogPoolsResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KLOG ListLogPoolsResponse decode error", zap.Error(err))
			return err
		}
		if len(response.LogPools) == 0 {
			break
		}

		for i := range response.LogPools {
			res <- Detail{
				Pool: response.LogPools[i],
			}
		}
		count += len(response.LogPools)
		if count >= *response.Total || len(response.LogPools) < size {
			break
		}
		request.Page = common.IntPtr(*request.Page + 1)
	}

	return nil
}
