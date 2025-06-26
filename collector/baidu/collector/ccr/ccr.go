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

package ccr

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/eccr"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	Instance *eccr.InstanceInfo
	Registry []*eccr.RegistryResponse
	NetWorks *eccr.ListPublicNetworksResponse
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CCR,
		ResourceTypeName:   collector.CCR,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://cloud.baidu.com/doc/CCR/s/qlxbkapbx`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.id",
			ResourceName: "$.Instance.name",
		},
		Regions: []string{
			"ccr.bj.baidubce.com",
			"ccr.bd.baidubce.com",
			"ccr.gz.baidubce.com",
			"ccr.su.baidubce.com",
			"ccr.fwh.baidubce.com",
			"ccr.hkg.baidubce.com",
			"ccr.cd.baidubce.com",
			"ccr.yq.baidubce.com",
		},
		Dimension: schema.Regional,
	}
}
func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CCRClient
	arg := &eccr.ListInstancesArgs{
		PageNo:   0,
		PageSize: 50,
	}

	total := 0
	for {
		response, err := client.ListInstances(arg)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstances error", zap.Error(err))
			return err
		}
		for _, i := range response.Instances {
			d := Detail{
				Instance: i,
				Registry: listRegistries(ctx, client, i.ID),
				NetWorks: getPublicNetWork(ctx, client, i.ID),
			}
			res <- d
		}
		total += len(response.Instances)
		if total >= response.Total {
			break
		}
		arg.PageNo++
	}
	return nil
}

func getPublicNetWork(ctx context.Context, client *eccr.Client, id string) *eccr.ListPublicNetworksResponse {
	networks, err := client.ListPublicNetworks(id)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPublicNetworks error", zap.Error(err))
		return nil
	}
	return networks
}

func listRegistries(ctx context.Context, client *eccr.Client, id string) (result []*eccr.RegistryResponse) {
	arg := &eccr.ListRegistriesArgs{
		PageNo:   0,
		PageSize: 50,
	}

	total := 0
	for {
		response, err := client.ListRegistries(id, arg)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListRegistries error", zap.Error(err))
			return
		}
		result = append(result, response.Items...)
		total += len(response.Items)
		if total >= response.Total {
			break
		}
		arg.PageNo++
	}

	return result
}
