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

package cfw

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/cfw"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	Cfw cfw.Cfw
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.CFW,
		ResourceTypeName:  collector.CFW,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.baidu.com/doc/CFW/index.html`,
		Regions:           []string{"cfw.baidubce.com"},
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*collector.Services).CFWClient

			total := 0
			args := &cfw.ListCfwArgs{
				Marker:  "",
				MaxKeys: 20,
			}
			for {
				response, err := client.ListCfw(args)
				if err != nil {
					log.CtxLogger(ctx).Warn("ListCfw error", zap.Error(err))
					return err
				}
				for _, item := range response.Cfws {
					d := Detail{
						Cfw: item,
					}
					total++
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
			ResourceId:   "$.Cfw.cfwId",
			ResourceName: "$.Cfw.name",
		},
		Dimension: schema.Global,
	}
}
