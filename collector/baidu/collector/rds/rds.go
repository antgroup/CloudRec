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

package rds

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/rds"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	Instance    rds.Instance
	SecurityIps []string
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.RDS,
		ResourceTypeName:  "RDS",
		ResourceGroupType: constant.DATABASE,
		Desc:              `https://cloud.baidu.com/doc/RDS/index.html`,
		Regions: []string{
			"rds.bj.baidubce.com",
			"rds.bd.baidubce.com",
			"rds.gz.baidubce.com",
			"rds.su.baidubce.com",
			"rds.fwh.baidubce.com",
			"rds.fsh.baidubce.com",
			"rds.cd.baidubce.com",
			"rds.nj.baidubce.com",
		},
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*collector.Services).RDSClient

			args := &rds.ListRdsArgs{}
			for {
				response, err := client.ListRds(args)
				if err != nil {
					log.CtxLogger(ctx).Warn("ListRds error", zap.Error(err))
					return err
				}
				for _, i := range response.Instances {
					d := Detail{
						Instance:    i,
						SecurityIps: getSecurityIps(ctx, client, i.InstanceId),
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
			ResourceId:   "$.Instance.instanceId",
			ResourceName: "$.Instance.instanceName",
		},
		Dimension: schema.Regional,
	}
}

func getSecurityIps(ctx context.Context, client *rds.Client, instanceId string) []string {
	resp, err := client.GetSecurityIps(instanceId)
	if err != nil {
		log.CtxLogger(ctx).Warn("getSecurityIps error", zap.Error(err))
		return nil
	}
	return resp.SecurityIps
}
