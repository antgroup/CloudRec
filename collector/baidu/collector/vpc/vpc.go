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

package vpc

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/vpc"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	VPC vpc.VPC
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.VPC,
		ResourceTypeName:  collector.VPC,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.baidu.com/product/vpc.html`,
		Regions: []string{
			"bcc.bj.baidubce.com",
			"bcc.gz.baidubce.com",
			"bcc.su.baidubce.com",
			"bcc.hkg.baidubce.com",
			"bcc.fwh.baidubce.com",
			"bcc.bd.baidubce.com",
			"bcc.cd.baidubce.com",
			"bcc.fsh.baidubce.com",
		},
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*collector.Services).VPCClient

			count := 0
			args := &vpc.ListVPCArgs{}
			for {
				response, err := client.ListVPC(args)
				if err != nil {
					log.CtxLogger(ctx).Warn("ListVPC error", zap.Error(err))
					return err
				}
				for _, i := range response.VPCs {
					d := Detail{
						VPC: i,
					}

					res <- d
					count++
				}
				if response.NextMarker == "" {
					break
				}
				args.Marker = response.NextMarker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.VPC.vpcId",
			ResourceName: "$.VPC.name",
		},
		Dimension: schema.Regional,
	}
}
