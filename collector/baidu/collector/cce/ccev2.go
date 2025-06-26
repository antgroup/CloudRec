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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/cce/v2"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	Cluster           *v2.Cluster
	InstanceGroupList []*v2.InstanceGroup
	KubeConfig        string
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CCE,
		ResourceTypeName:   collector.CCE,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://cloud.baidu.com/doc/CCE/s/nkwopebgf`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Cluster.spec.clusterID",
			ResourceName: "$.Cluster.spec.clusterName",
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
func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
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
			d := Detail{
				Cluster:           cluster,
				KubeConfig:        getKubeConfig(ctx, client, cluster.Spec.ClusterID),
				InstanceGroupList: listInstanceGroups(ctx, client, cluster.Spec.ClusterID),
			}
			res <- d
		}
		if total >= response.ClusterPage.TotalCount {
			break
		}
		arg.PageNum++
	}
	return nil
}

func getKubeConfig(ctx context.Context, client *v2.Client, uuid string) string {
	arg := &v2.GetKubeConfigArgs{
		ClusterID: uuid,
	}
	response, err := client.GetKubeConfig(arg)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetClusterKubeConfig error", zap.Error(err))
		return ""
	}
	return response.KubeConfig
}

func listInstanceGroups(ctx context.Context, client *v2.Client, uuid string) (list []*v2.InstanceGroup) {
	arg := &v2.ListInstanceGroupsArgs{
		ClusterID: uuid,
		ListOption: &v2.InstanceGroupListOption{
			PageSize: 10,
			PageNo:   1,
		},
	}

	total := 0
	for {
		response, err := client.ListInstanceGroups(arg)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstanceGroups error", zap.Error(err))
			return
		}
		total = total + len(response.Page.List)
		list = append(list, response.Page.List...)

		if total >= response.Page.TotalCount {
			break
		}

		arg.ListOption.PageNo++
	}

	return list
}
