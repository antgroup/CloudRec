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

package security_group

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/baidubce/bce-sdk-go/services/bcc/api"
	"github.com/cloudrec/baidu/collector"
	"go.uber.org/zap"
)

type Detail struct {
	SecurityGroup api.SecurityGroupModel
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.SECURITY_GROUP,
		ResourceTypeName:  collector.SECURITY_GROUP,
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
			client := service.(*collector.Services).BCCClient

			count := 0
			queryArgs := &api.ListSecurityGroupArgs{}
			for {
				response, err := client.ListSecurityGroup(queryArgs)
				if err != nil {
					log.CtxLogger(ctx).Warn("ListSecurityGroup error", zap.Error(err))
					return err
				}
				for _, i := range response.SecurityGroups {
					d := Detail{
						SecurityGroup: i,
					}

					res <- d
					count++
				}
				if response.NextMarker == "" {
					break
				}
				queryArgs.Marker = response.NextMarker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.SecurityGroup.id",
			ResourceName: "$.SecurityGroup.name",
		},
		Dimension: schema.Regional,
	}
}
