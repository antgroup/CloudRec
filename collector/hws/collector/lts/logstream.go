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

package lts

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/lts/v2/model"
	"go.uber.org/zap"
)

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.LTS,
		ResourceTypeName:   "LTS LogStream",
		ResourceGroupType:  constant.LOG,
		Desc:               `https://console.huaweicloud.com/apiexplorer/#/openapi/LTS/doc?api=CreateLogGroup`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.LogStream.log_stream_id",
			ResourceName: "$.LogStream.log_stream_name",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	LogStream model.ListLogStreamsResponseBody1LogStreams
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.LTS
	request := &model.ListLogStreamsRequest{}
	response, err := cli.ListLogStreams(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListLogStreams error", zap.Error(err))
		return err
	}

	for _, logStream := range *response.LogStreams {
		res <- &Detail{
			LogStream: logStream,
		}
	}
	return nil
}
