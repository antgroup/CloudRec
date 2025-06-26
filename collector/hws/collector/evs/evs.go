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

package evs

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/evs/v2/model"
	"go.uber.org/zap"
)

func GetVolumeResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EVS,
		ResourceTypeName:   "EVS Volumes",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/EVS/sdk?api=ListVolumes",
		ResourceDetailFunc: GetVolumeDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Volume.id",
			ResourceName: "$.Volume.name",
		},
		Dimension: schema.Regional,
	}
}

type VolumeDetail struct {
	Volume model.VolumeDetail
}

func GetVolumeDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).EVS

	limit := int32(50)
	offset := int32(1)
	request := &model.ListVolumesRequest{
		Limit:  &limit,
		Offset: &offset,
	}
	for {
		response, err := cli.ListVolumes(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListVolumes error", zap.Error(err))
			return err
		}

		for _, volume := range *response.Volumes {
			res <- &VolumeDetail{
				Volume: volume,
			}
		}

		if len(*response.Volumes) < int(limit) {
			break
		}

		*request.Offset = *request.Offset + 1
	}
	return nil
}
