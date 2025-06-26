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

package eip

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/eip"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	Eip eip.EipModel
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.EIP,
		ResourceTypeName:  collector.EIP,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.baidu.com/product/eip.html`,
		Regions: []string{
			"eip.bj.baidubce.com",
			"eip.gz.baidubce.com",
			"eip.su.baidubce.com",
			"eip.hkg.baidubce.com",
			"eip.fwh.baidubce.com",
			"eip.bd.baidubce.com",
		},
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*collector.Services).EIPClient

			args := &eip.ListEipArgs{}
			for {
				response, err := client.ListEip(args)
				if err != nil {
					log.CtxLogger(ctx).Warn("ListEip error", zap.Error(err))
					return err
				}
				for _, i := range response.EipList {
					d := Detail{
						Eip: i,
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
			ResourceId:   "$.Eip.eipId",
			ResourceName: "$.Eip.name",
			Address:      "$.Eip.eip",
		},
		Dimension: schema.Regional,
	}
}
