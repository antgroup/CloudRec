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

package ack

import (
	"context"
	cs20151215 "github.com/alibabacloud-go/cs-20151215/v5/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ACKCluster,
		ResourceTypeName:   collector.ACKCluster,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               "https://api.aliyun.com/product/CS",
		ResourceDetailFunc: GetClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.cluster_id",
			ResourceName: "$.Cluster.name",
		},
		Dimension: schema.Global,
	}
}

type Detail struct {
	Cluster                 *cs20151215.DescribeClustersV1ResponseBodyClusters
	AssociatedResource      []*cs20151215.DescribeClusterResourcesResponseBody
	ClusterKubeconfigStates []*cs20151215.ListClusterKubeconfigStatesResponseBodyStates
}

func GetClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ACK

	var page int64 = 1
	request := &cs20151215.DescribeClustersV1Request{}
	request.PageNumber = tea.Int64(page)
	request.PageSize = tea.Int64(10)
	count := 0
	for {
		resp, err := cli.DescribeClustersV1(request)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeClustersV1 error", zap.Error(err))
			return err
		}
		count += len(resp.Body.Clusters)
		for i := 0; i < len(resp.Body.Clusters); i++ {
			res <- Detail{
				Cluster:                 resp.Body.Clusters[i],
				AssociatedResource:      describeClusterResources(ctx, cli, resp.Body.Clusters[i].ClusterId),
				ClusterKubeconfigStates: listClusterKubeconfigStates(ctx, cli, resp.Body.Clusters[i].ClusterId),
			}
		}
		if count >= int(*resp.Body.PageInfo.TotalCount) || len(resp.Body.Clusters) == 0 {
			break
		}
		page += 1
		request.PageNumber = tea.Int64(page)
	}
	return nil
}

func listClusterKubeconfigStates(ctx context.Context, cli *cs20151215.Client, id *string) (states []*cs20151215.ListClusterKubeconfigStatesResponseBodyStates) {
	request := &cs20151215.ListClusterKubeconfigStatesRequest{}

	count := 0
	for {
		out, err := cli.ListClusterKubeconfigStates(id, request)
		if err != nil {
			log.CtxLogger(ctx).Error("ListClusterKubeconfigStates error", zap.Error(err))
			return nil
		}
		states = append(states, out.Body.States...)

		count += len(out.Body.States)
		if count >= int(*out.Body.Page.TotalCount) || len(out.Body.States) == 0 {
			break
		}
		request.PageNumber = tea.Int32(*out.Body.Page.PageNumber + 1)
	}

	return states
}

func describeClusterResources(ctx context.Context, cli *cs20151215.Client, id *string) []*cs20151215.DescribeClusterResourcesResponseBody {
	out, err := cli.DescribeClusterResources(id, &cs20151215.DescribeClusterResourcesRequest{})
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeClusterResources error", zap.Error(err))
		return nil
	}
	return out.Body
}
