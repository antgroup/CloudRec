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
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	"go.uber.org/zap"
)

func GetEIPResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EIP,
		ResourceTypeName:   "EIP",
		ResourceGroupType:  constant.NET,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/EIP/doc?api=ListPublicips&version=v2",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.PublicIpShowResp.id",
			ResourceName: "$.PublicIpShowResp.id",
			Address:      "$.PublicIpShowResp.public_ip_address",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	PublicIpShowResp model.PublicipShowResp
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).EIP

	limit := int32(10)
	request := &model.ListPublicipsRequest{
		Limit: &limit,
	}
	for {
		response, err := cli.ListPublicips(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListPublicips error", zap.Error(err))
			return err
		}

		for _, publicIp := range *response.Publicips {
			res <- &Detail{
				PublicIpShowResp: publicIp,
			}
		}

		if len(*response.Publicips) < int(limit) {
			break
		}

		publicId := (*response.Publicips)[len(*response.Publicips)-1]

		request.Marker = publicId.Id
	}
	return nil
}
