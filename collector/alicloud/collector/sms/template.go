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

package sms

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetSMSTemplateResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SMSTemplate,
		ResourceTypeName:   collector.SMSTemplate,
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/Dysmsapi`,
		ResourceDetailFunc: GetSMSTemplateDetail,
		RowField: schema.RowField{
			ResourceId:   "$.TemplateCode",
			ResourceName: "$.TemplateName",
		},
		Dimension: schema.Global,
	}
}

type SMSTemplateDetail struct {
	Template dysmsapi.SmsStatsResultDTO
}

func GetSMSTemplateDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Dysmsapi
	if cli == nil {
		log.CtxLogger(ctx).Warn("Dysmsapi client is nil")
		return nil
	}

	pageSize := 50
	currentPage := 1

	for {
		request := dysmsapi.CreateQuerySmsTemplateListRequest()
		request.Scheme = "https"
		request.PageSize = requests.NewInteger(pageSize)
		request.PageIndex = requests.NewInteger(currentPage)

		response, err := cli.QuerySmsTemplateList(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("QuerySmsTemplateList error", zap.Error(err))
			return err
		}

		if len(response.SmsTemplateList) == 0 {
			break
		}

		for _, template := range response.SmsTemplateList {
			detail := &SMSTemplateDetail{
				Template: template,
			}
			res <- detail
		}

		// Simple pagination check - if we got fewer than page size items, we're done
		if len(response.SmsTemplateList) < pageSize {
			break
		}

		currentPage++
	}

	return nil
}
