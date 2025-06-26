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

package blb

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/blb"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	Blb                         blb.BLBModel
	ListenerList                []blb.AllListenerModel
	BlbSecurityGroups           []blb.BlbSecurityGroupModel
	BlbEnterpriseSecurityGroups []blb.BlbEnterpriseSecurityGroupModel
	BackendServerList           []blb.BackendServerModel
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.BLB,
		ResourceTypeName:  "BLB",
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.baidu.com/doc/BLB/index.html`,
		Regions: []string{
			"blb.bj.baidubce.com",
			"blb.gz.baidubce.com",
			"blb.su.baidubce.com",
			"blb.hkg.baidubce.com",
			"blb.fwh.baidubce.com",
			"blb.bd.baidubce.com",
			"blb.fsh.baidubce.com",
			"blb.sin.baidubce.com",
		},
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*collector.Services).BLBClient

			args := &blb.DescribeLoadBalancersArgs{}
			for {
				response, err := client.DescribeLoadBalancers(args)
				if err != nil {
					log.CtxLogger(ctx).Warn("DescribeLoadBalancers error", zap.Error(err))
					return err
				}
				for _, i := range response.BlbList {
					d := Detail{
						Blb:                         i,
						ListenerList:                describeAllListeners(ctx, client, i.BlbId),
						BlbSecurityGroups:           describeSecurityGroups(ctx, client, i.BlbId),
						BlbEnterpriseSecurityGroups: describeEnterpriseSecurityGroups(ctx, client, i.BlbId),
						BackendServerList:           describeBackendServers(ctx, client, i.BlbId),
					}
					res <- d
				}
				if response.NextMarker == "" {
					break
				}
				args.Marker = response.NextMarker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Blb.blbId",
			ResourceName: "$.Blb.name",
			Address:      "$.Blb.publicIp",
		},
		Dimension: schema.Regional,
	}
}

func describeAllListeners(ctx context.Context, client *blb.Client, blbId string) (listenerList []blb.AllListenerModel) {
	args := &blb.DescribeListenerArgs{
		Marker:  "",
		MaxKeys: 50,
	}

	for {
		response, err := client.DescribeAllListeners(blbId, args)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeAllListeners error", zap.Error(err))
			return
		}
		listenerList = append(listenerList, response.AllListenerList...)
		if response.NextMarker == "" {
			break
		}
		args.Marker = response.NextMarker
	}

	return listenerList
}

func describeSecurityGroups(ctx context.Context, client *blb.Client, blbId string) []blb.BlbSecurityGroupModel {
	resp, err := client.DescribeSecurityGroups(blbId)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeSecurityGroups error", zap.Error(err))
		return nil
	}

	return resp.BlbSecurityGroups
}

func describeEnterpriseSecurityGroups(ctx context.Context, client *blb.Client, blbId string) []blb.BlbEnterpriseSecurityGroupModel {
	resp, err := client.DescribeEnterpriseSecurityGroups(blbId)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeEnterpriseSecurityGroups error", zap.Error(err))
		return nil
	}

	return resp.BlbEnterpriseSecurityGroups
}

func describeBackendServers(ctx context.Context, client *blb.Client, blbId string) (backendServerList []blb.BackendServerModel) {
	args := &blb.DescribeBackendServersArgs{
		Marker:  "",
		MaxKeys: 50,
	}
	for {
		response, err := client.DescribeBackendServers(blbId, args)
		if err != nil {
			log.CtxLogger(ctx).Warn("describeBackendServers error", zap.Error(err))
			return
		}
		backendServerList = append(backendServerList, response.BackendServerList...)
		if response.NextMarker == "" {
			break
		}
		args.Marker = response.NextMarker
	}

	return backendServerList
}
