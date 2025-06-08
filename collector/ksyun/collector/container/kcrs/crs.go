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

package kcrs

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kcrs "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kcrs/v20211109"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strconv"
	"strings"
)

type KSyunKCRSDetail struct {
	Instance     any
	Repositories []any
}

func GetKCRSResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KCRS,
		ResourceTypeName:  collector.KCRS,
		ResourceGroupType: constant.CONTAINER,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/211/1011`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KCRS
			request := kcrs.NewDescribeInstanceRequest()
			maxPerRequest := 20
			request.MaxResults = common.StringPtr("20")
			request.Marker = common.StringPtr("0")
			count := 0

			for {
				responseStr := cli.DescribeInstanceWithContext(ctx, request)
				collector.ShowResponse(ctx, "KCRS", "DescribeInstance", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCRS DescribeInstance error", zap.Error(err))
					return err
				}

				response := kcrs.NewDescribeInstanceResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCRS DescribeInstanceResponse decode error", zap.Error(err))
					return err
				}
				if len(response.InstanceSet) == 0 {
					break
				}

				for i := range response.InstanceSet {
					item := &response.InstanceSet[i]
					res <- &KSyunKCRSDetail{
						Instance:     item,
						Repositories: getRepositories(ctx, cli, item.InstanceId),
					}
				}

				count += len(response.InstanceSet)
				if len(response.InstanceSet) < maxPerRequest {
					break
				}
				request.Marker = common.StringPtr(strconv.Itoa(count))
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Regions: []string{
			"cn-beijing-6",   // 华北1（北京）
			"cn-shanghai-2",  // 华东1（上海）
			"cn-guangzhou-1", // 华南1（广州）
			"cn-northwest-1", // 西北1（庆阳）
			"cn-ningbo-1",    // 华东2（宁波）
			"cn-northwest-4", // 西北4（海东）
		},
		Dimension: schema.Regional,
	}
}

func getRepositories(ctx context.Context, cli *kcrs.Client, insId *string) (res []any) {
	request := kcrs.NewDescribeNamespaceRequest()
	request.InstanceId = insId
	maxPerRequest := 20
	request.MaxResults = common.StringPtr("20")
	request.Marker = common.StringPtr("0")
	count := 0

	for {
		responseStr := cli.DescribeNamespaceWithContext(ctx, request)
		collector.ShowResponse(ctx, "KCRS", "DescribeNamespace", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCRS DescribeNamespace error", zap.Error(err))
			return res
		}

		response := kcrs.NewDescribeNamespaceResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCRS DescribeNamespaceResponse decode error", zap.Error(err))
			return
		}
		if len(response.NamespaceSet) == 0 {
			break
		}

		for i := range response.NamespaceSet {
			res = append(res, getRepoPerNamespace(ctx, cli, insId, response.NamespaceSet[i].Namespace)...)
		}

		count += len(response.NamespaceSet)
		if len(response.NamespaceSet) < maxPerRequest {
			break
		}
		request.Marker = common.StringPtr(strconv.Itoa(count))
	}
	return
}

func getRepoPerNamespace(ctx context.Context, cli *kcrs.Client, insId *string, ns *string) (repo []any) {
	request := kcrs.NewDescribeRepositoryRequest()
	request.InstanceId = insId
	request.Namespace = ns
	request.MaxResults = common.StringPtr("20")
	request.Marker = common.StringPtr("0")
	count := 0

	for {
		responseStr := cli.DescribeRepositoryWithContext(ctx, request)
		collector.ShowResponse(ctx, "KCRS", "DescribeRepository", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCRS DescribeRepository error", zap.Error(err))
			return repo
		}

		response := kcrs.NewDescribeRepositoryResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCRS DescribeRepositoryResponse decode error", zap.Error(err))
			return repo
		}
		if len(response.RepoSet) == 0 {
			break
		}

		for i := range response.RepoSet {
			item := &response.RepoSet[i]
			repo = append(repo, item)
		}

		count += len(response.RepoSet)
		if count >= *response.TotalCount {
			break
		}
		request.Marker = common.StringPtr(strconv.Itoa(count))
	}
	return repo
}
