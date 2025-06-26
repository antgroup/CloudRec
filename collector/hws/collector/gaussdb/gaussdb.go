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

package gaussDB

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/gaussdbfornosql/v3/model"
	"go.uber.org/zap"
)

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.GaussDB,
		ResourceTypeName:   "GaussDB",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/GaussDBforNoSQL/debug?api=ListInstances",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.id",
			ResourceName: "$.Instance.name",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Instance model.ListInstancesResult
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).GaussDBForNoSQL

	limit := int32(50)
	offset := int32(0)
	request := &model.ListInstancesRequest{
		Limit:  &limit,
		Offset: &offset,
	}
	for {
		response, err := cli.ListInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstances error", zap.Error(err))
			return err
		}

		for _, instance := range *response.Instances {
			res <- &Detail{
				Instance: instance,
			}
		}

		if len(*response.Instances) < int(limit) {
			break
		}

		*request.Offset = *request.Offset + 1
	}
	return nil
}
