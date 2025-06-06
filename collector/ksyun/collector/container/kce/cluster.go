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

package kce

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kce "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kce/v20231115"
	kce2 "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kce2/v20230101"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type KSyunKCEDetail struct {
	Cluster any
}

func GetKCEResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KCE,
		ResourceTypeName:  collector.KCE,
		ResourceGroupType: constant.CONTAINER,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/0/1007`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			err := getKCEDetail(ctx, service.(*collector.Services).KCE, res)
			if err != nil {
				return err
			}
			err = getKCE2Detail(ctx, service.(*collector.Services).KCE2, res)
			if err != nil {
				return err
			}
			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.ClusterId",
			ResourceName: "$.Cluster.ClusterName",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"ap-singapore-1",  // 新加坡
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-beijing-fin",  // 华北金融1（北京）
			"cn-northwest-1",  // 西北1（庆阳）
			"cn-northwest-3",  // 西北3区（宁夏）
			"cn-north-vip1",   // 华北专属1区（天津-小米）
			"cn-ningbo-1",     // 华东2（宁波）
			"cn-northwest-4",  // 西北4（海东）
		},
		Dimension: schema.Global,
	}
}

func getKCEDetail(ctx context.Context, cli *kce.Client, res chan<- any) error {
	request := kce.NewDescribeClusterRequest()
	request.MaxResults = common.IntPtr(10)
	request.Marker = common.IntPtr(0)
	count := 0

	for {
		responseStr := cli.DescribeClusterWithContext(ctx, request)
		collector.ShowResponse(ctx, collector.KCE, "DescribeCluster", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCE DescribeCluster error", zap.Error(err))
			return err
		}

		response := kce.NewDescribeClusterResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCE DescribeClusterResponse decode error", zap.Error(err))
			return err
		}
		if len(response.ClusterSet) == 0 {
			break
		}

		for i := range response.ClusterSet {
			res <- &KSyunKCEDetail{
				Cluster: &response.ClusterSet[i],
			}
		}
		count += len(response.ClusterSet)
		if count >= *response.TotalCount {
			break
		}

		request.Marker = response.Marker
	}

	return nil
}

func getKCE2Detail(ctx context.Context, cli *kce2.Client, res chan<- any) error {
	request := kce2.NewDescribeClustersRequest()
	request.MaxResults = common.IntPtr(20)
	request.Marker = common.IntPtr(0)
	count := 0

	for {
		responseStr := cli.DescribeClustersWithContext(ctx, request)
		collector.ShowResponse(ctx, "KCE2", "DescribeClusters", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCE2 DescribeClusters error", zap.Error(err))
			return err
		}

		response := kce2.NewDescribeClustersResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCE2 DescribeClustersResponse decode error", zap.Error(err))
			return err
		}
		if len(response.Data.ClusterSet) == 0 {
			break
		}

		for i := range response.Data.ClusterSet {
			res <- &KSyunKCEDetail{
				Cluster: &response.Data.ClusterSet[i],
			}
		}

		count += len(response.Data.ClusterSet)
		if count >= *response.Data.TotalCount {
			break
		}

		request.Marker = common.IntPtr(count)
	}

	return nil
}
