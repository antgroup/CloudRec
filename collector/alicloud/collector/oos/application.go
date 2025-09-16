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

package oos

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/oos"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetOOSApplicationResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.OOSApplication,
		ResourceTypeName:   collector.OOSApplication,
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               `https://api.aliyun.com/product/Oos`,
		ResourceDetailFunc: GetApplicationDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Application.ServiceId",
			ResourceName: "$.Application.Name",
		},
		Dimension: schema.Global,
	}
}

type ApplicationDetail struct {
	Application oos.Application
}

func GetApplicationDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).OOS

	request := oos.CreateListApplicationsRequest()
	request.Scheme = "https"
	request.MaxResults = "50"

	for {
		response, err := cli.ListApplications(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListApplications error", zap.Error(err))
			return err
		}

		for _, app := range response.Applications {
			// Get detailed application information
			appDetail := getApplication(ctx, cli, app.Name)

			d := ApplicationDetail{
				Application: appDetail,
			}

			res <- d
		}

		if response.NextToken == "" {
			break
		}
		request.NextToken = response.NextToken
	}
	return nil
}

func getApplication(ctx context.Context, cli *oos.Client, name string) oos.Application {
	request := oos.CreateGetApplicationRequest()
	request.Scheme = "https"
	request.Name = name

	response, err := cli.GetApplication(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetApplication error", zap.Error(err), zap.String("application", name))
		return oos.Application{}
	}

	return response.Application
}
