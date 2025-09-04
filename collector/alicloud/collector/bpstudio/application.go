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

package bpstudio

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/bpstudio"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"strconv"
)

func GetBPStudioApplicationResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.BPStudioApplication,
		ResourceTypeName:   collector.BPStudioApplication,
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               `https://api.aliyun.com/product/BPStudio`,
		ResourceDetailFunc: GetApplicationDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Application.ApplicationId",
			ResourceName: "$.Application.Name",
		},
		Dimension: schema.Global,
	}
}

type ApplicationDetail struct {
	Application       bpstudio.Item
	ApplicationDetail bpstudio.Data
}

func GetApplicationDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).BPStudio

	request := bpstudio.CreateListApplicationRequest()
	request.Scheme = "https"
	request.MaxResults = "20"

	for {
		response, err := cli.ListApplication(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListApplication error", zap.Error(err))
			return err
		}

		for _, app := range response.Data {
			d := ApplicationDetail{
				Application:       app,
				ApplicationDetail: getApplication(ctx, cli, app.ApplicationId),
			}
			res <- d
		}

		if response.NextToken == 0 {
			break
		}
		request.NextToken = requests.Integer(strconv.Itoa(response.NextToken))
	}
	return nil
}

func getApplication(ctx context.Context, cli *bpstudio.Client, applicationId string) (application bpstudio.Data) {
	request := bpstudio.CreateGetApplicationRequest()
	request.Scheme = "https"
	request.ApplicationId = applicationId

	response, err := cli.GetApplication(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetApplication error", zap.Error(err))
		return
	}

	return response.Data
}
