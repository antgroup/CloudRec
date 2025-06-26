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

package cas

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	cas20200407 "github.com/alibabacloud-go/cas-20200407/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetCERTResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CERT,
		ResourceTypeName:   "CERT",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/cas`,
		ResourceDetailFunc: GetCertificateOrderDetail,
		RowField: schema.RowField{
			ResourceId:   "$.CertificateOrder.InstanceId",
			ResourceName: "$.CertificateOrder.Name",
		},
		Regions: []string{
			"cn-hangzhou",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"me-east-1",
		},
		Dimension: schema.Regional,
	}
}

type CertificateOrderDetail struct {
	CertificateOrder *cas20200407.ListUserCertificateOrderResponseBodyCertificateOrderList
}

func GetCertificateOrderDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CAS

	request := &cas20200407.ListUserCertificateOrderRequest{}
	request.OrderType = tea.String("CERT")
	request.ShowSize = tea.Int64(50)
	request.CurrentPage = tea.Int64(1)

	var count int64
	for {
		response, err := cli.ListUserCertificateOrderWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Error("ListUserCertificateOrderWithOptions error", zap.Error(err))
			return err
		}

		for _, cert := range response.Body.CertificateOrderList {
			d := CertificateOrderDetail{
				CertificateOrder: cert,
			}

			res <- d
		}

		count += int64(len(response.Body.CertificateOrderList))

		if count >= *response.Body.TotalCount {
			break
		}

		*request.CurrentPage = *request.CurrentPage + 1
	}

	return nil
}
