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

package cce

import (
	"context"

	v2 "github.com/baidubce/bce-sdk-go/services/cce/v2"
	"github.com/cloudrec/baidu/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

type NodeDetail struct {
	Instance *v2.Instance
}

func GetNodeResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CCE_NODE,
		ResourceTypeName:   collector.CCE_NODE,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://cloud.baidu.com/doc/CCE/s/nkwopebgf`,
		ResourceDetailFunc: GetNodeDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.spec.cceInstanceID",
			ResourceName: "$.Instance.spec.instanceName",
		},
		Regions: []string{
			"cce.bj.baidubce.com",
			"cce.gz.baidubce.com",
			"cce.su.baidubce.com",
			"cce.bd.baidubce.com",
			"cce.fwh.baidubce.com",
			"cce.hkg.baidubce.com",
			"cce.yq.baidubce.com",
			"cce.cd.baidubce.com",
			"cce.nj.baidubce.com",
		},
		Dimension: schema.Regional,
	}
}

func GetNodeDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CCEClient

	arg := &v2.ListClustersArgs{
		PageSize: 10,
		PageNum:  1,
	}
	total := 0
	for {
		response, err := client.ListClusters(arg)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListClusters error", zap.Error(err))
			return err
		}
		for _, cluster := range response.ClusterPage.ClusterList {
			total++
			err := listInstances(ctx, client, cluster.Spec.ClusterID, res)
			if err != nil {
				log.CtxLogger(ctx).Warn("listInstances error", zap.Error(err))
				return err
			}
		}
		if total >= response.ClusterPage.TotalCount {
			break
		}
		arg.PageNum++
	}
	return nil
}

func listInstances(ctx context.Context, client *v2.Client, clusterID string, res chan<- any) error {
	arg := &v2.ListInstancesByPageArgs{
		ClusterID: clusterID,
		Params: &v2.ListInstancesByPageParams{
			PageSize: 20,
			PageNo:   1,
		},
	}
	total := 0
	for {
		response, err := client.ListInstancesByPage(arg)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstancesByPage error", zap.Error(err))
			return err
		}
		total = total + len(response.InstancePage.InstanceList)
		for _, instance := range response.InstancePage.InstanceList {
			d := NodeDetail{
				Instance: instance,
			}
			res <- d
		}
		if total >= response.InstancePage.TotalCount {
			break
		}
		arg.Params.PageNo++
	}
	return nil
}
