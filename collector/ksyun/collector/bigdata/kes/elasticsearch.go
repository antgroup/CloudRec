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

package kes

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kes "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kes/v20201215"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type Detail struct {
	Cluster any
}

func GetKESResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KES,
		ResourceTypeName:  collector.KES,
		ResourceGroupType: constant.BIGDATA,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/143/1049`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KES
			request := kes.NewListClustersRequest()
			count := 0
			limit := 100
			request.Marker = common.StringPtr(fmt.Sprintf("limit=%d&offset=%d", limit, count))

			for {
				responseStr := cli.ListClustersWithContext(ctx, request)
				collector.ShowResponse(ctx, "KES", "ListClusters", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KES ListClusters error", zap.Error(err))
					return err
				}

				response := kes.NewListClustersResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KES ListClusters decode error", zap.Error(err))
					return err
				}
				if len(response.Clusters) == 0 {
					break
				}

				for i := range response.Clusters {
					cl, e := describeCluster(ctx, cli, response.Clusters[i].ClusterId)
					if e == nil {
						res <- Detail{
							Cluster: cl,
						}
						continue
					}
					res <- Detail{
						Cluster: &response.Clusters[i],
					}
				}
				count += len(response.Clusters)
				if count >= *response.Total {
					break
				}
				request.Marker = common.StringPtr(fmt.Sprintf("limit=%d&offset=%d", limit, count))
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.ClusterId",
			ResourceName: "$.Cluster.ClusterName",
		},
		Regions: []string{
			"cn-beijing-6",   // 华北1（北京）
			"cn-shanghai-2",  // 华东1（上海）
			"cn-guangzhou-1", // 华南1（广州）
			"ap-singapore-1", // 新加坡
			"eu-east-1",      // 俄罗斯（莫斯科）
			"cn-taipei-1",    // 台北
			"cn-beijing-fin", // 华北金融1（北京）
			"cn-northwest-1", // 西北1（庆阳）
			"cn-northwest-3", // 西北3区（宁夏）
			"cn-north-vip1",  // 华北专属1区（天津-小米）
			"cn-northwest-4", // 西北4（海东）
		},
		Dimension: schema.Global,
	}
}

func describeCluster(ctx context.Context, cli *kes.Client, clusterId *string) (any, error) {
	request := kes.NewDescribeClusterRequest()
	request.ClusterId = clusterId

	responseStr := cli.DescribeClusterWithContext(ctx, request)
	collector.ShowResponse(ctx, "KES", "DescribeCluster", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KES DescribeCluster error", zap.Error(err))
		return nil, err
	}

	response := make(map[string]any)
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(&response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KES DescribeCluster decode error", zap.Error(err))
		return nil, err
	}

	return response, nil
}
