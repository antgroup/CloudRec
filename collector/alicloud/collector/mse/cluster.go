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

package mse

import (
	"context"
	"strings"

	mse20190531 "github.com/alibabacloud-go/mse-20190531/v5/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetMSEClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MSECluster,
		ResourceTypeName:   "MSE Cluster",
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               "https://api.aliyun.com/product/mse",
		ResourceDetailFunc: GetClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.InstanceId",
			ResourceName: "$.Cluster.ClusterName",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-fuzhou",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"cn-wuhan-lr",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-zhengzhou-jva",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

type ClusterDetail struct {
	Cluster *mse20190531.QueryClusterDetailResponseBodyData
	Config  *mse20190531.QueryConfigResponseBodyData
}

const mseListPageSize int32 = 100

func GetClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).MSE

	regionId, _ := ctx.Value(constant.RegionId).(string)
	pageNum := int32(1)
	listClustersRequest := &mse20190531.ListClustersRequest{
		PageSize: tea.Int32(mseListPageSize),
		RegionId: tea.String(regionId),
	}
	for {
		listClustersRequest.PageNum = tea.Int32(pageNum)
		resp, err := cli.ListClusters(listClustersRequest)
		if err != nil {
			log.CtxLogger(ctx).Error("ListClusters error", zap.Error(err))
			return err
		}
		if resp == nil || resp.Body == nil || len(resp.Body.Data) == 0 {
			break
		}

		for _, cluster := range resp.Body.Data {
			clusterId := mseClusterID(cluster)
			res <- ClusterDetail{
				Cluster: queryClusterDetail(ctx, cli, cluster.InstanceId),
				Config:  queryConfig(ctx, cli, &clusterId, cluster.InstanceId),
			}
		}

		totalCount := tea.Int32Value(resp.Body.TotalCount)
		if totalCount == 0 || pageNum*mseListPageSize >= totalCount {
			break
		}
		pageNum++
	}

	return nil
}

func mseClusterID(cluster *mse20190531.ListClustersResponseBodyData) string {
	if cluster == nil || cluster.ClusterName == nil {
		return ""
	}
	parts := strings.Split(*cluster.ClusterName, "-")
	if len(parts) < 2 {
		return *cluster.ClusterName
	}
	return "mse-" + parts[1]
}

func queryConfig(ctx context.Context, cli *mse20190531.Client, clusterId *string, instanceId *string) *mse20190531.QueryConfigResponseBodyData {
	request := &mse20190531.QueryConfigRequest{
		ClusterId:  clusterId,
		InstanceId: instanceId,
	}
	resp, err := cli.QueryConfig(request)
	if err != nil {
		log.CtxLogger(ctx).Error("QueryConfig error", zap.Error(err))
		return nil
	}

	return resp.Body.Data
}

func queryClusterDetail(ctx context.Context, cli *mse20190531.Client, id *string) *mse20190531.QueryClusterDetailResponseBodyData {
	aclSwitch := true
	request := &mse20190531.QueryClusterDetailRequest{
		AclSwitch:  &aclSwitch,
		InstanceId: id,
	}
	resp, err := cli.QueryClusterDetail(request)
	if err != nil {
		log.CtxLogger(ctx).Error("QueryClusterDetail error", zap.Error(err))
		return nil
	}

	return resp.Body.Data
}
