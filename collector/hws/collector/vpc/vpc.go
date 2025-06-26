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
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	"go.uber.org/zap"
)

func GetVPCResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.VPC,
		ResourceTypeName:   "VPC",
		ResourceGroupType:  constant.NET,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/VPC/sdk?version=v2&api=ListVpcs",
		ResourceDetailFunc: GetVPCDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Vpc.id",
			ResourceName: "$.Vpc.name",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Vpc model.Vpc
}

func GetVPCDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPC

	limit := int32(50)
	request := &model.ListVpcsRequest{
		Limit: &limit,
	}
	for {
		response, err := cli.ListVpcs(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListVpcs error", zap.Error(err))
			return err
		}

		for _, vpc := range *response.Vpcs {
			res <- &Detail{
				Vpc: vpc,
			}
		}

		if len(*response.Vpcs) < int(limit) {
			break
		}

		vpc := (*response.Vpcs)[len(*response.Vpcs)-1]

		*request.Marker = vpc.Id
	}
	return nil
}
