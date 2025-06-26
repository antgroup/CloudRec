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

package sfs

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sfsturbo/v1/model"
	"go.uber.org/zap"
)

func GetShareResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SFSShare,
		ResourceTypeName:   "SFS Share",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/SFSTurbo/doc?api=ListShares",
		ResourceDetailFunc: GetShareDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ShareInfo.id",
			ResourceName: "$.ShareInfo.name",
		},
		Dimension: schema.Regional,
	}
}

type ShareDetail struct {
	ShareInfo model.ShareInfo
}

func GetShareDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).SFS

	limit := int64(50)
	offset := int64(0)
	request := &model.ListSharesRequest{
		Limit:  &limit,
		Offset: &offset,
	}
	for {
		response, err := cli.ListShares(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListShares error", zap.Error(err))
			return err
		}

		for _, share := range *response.Shares {
			res <- &ShareDetail{
				ShareInfo: share,
			}
		}

		if len(*response.Shares) < int(limit) {
			break
		}

		*request.Offset = *request.Offset + 1
	}
	return nil
}
