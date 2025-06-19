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

package kcm

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kcm "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kcm/v20160304"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strconv"
	"strings"
)

type ListCertificatesResponse struct {
	RequestId      *string `json:"RequestId" name:"RequestId"`
	CertificateSet []struct {
		CertificateId *string `json:"CertificateId" name:"CertificateId"`
	} `json:"CertificateSet" name:"CertificateSet"`
	PageCount *string `json:"PageCount" name:"PageCount"`
}

type ListCertificatesResponseAny struct {
	RequestId      *string `json:"RequestId" name:"RequestId"`
	CertificateSet []any   `json:"CertificateSet" name:"CertificateSet"`
	PageCount      *string `json:"PageCount" name:"PageCount"`
}

type GetCertificateDetailResponse struct {
	RequestId   *string `json:"RequestId" name:"RequestId"`
	Certificate any     `json:"Certificate" name:"Certificate"`
}

type Detail struct {
	Cert   any
	Detail any
}

func GetKCMResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KCM,
		ResourceTypeName:  collector.KCM,
		ResourceGroupType: constant.SECURITY,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/0/1061`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KCM
			request := kcm.NewListCertificatesRequest()
			count := 0
			size := 100
			request.PageSize = common.IntPtr(size)
			request.Page = common.IntPtr(1)

			for {
				responseStr := cli.ListCertificatesWithContext(ctx, request)
				collector.ShowResponse(ctx, "KCM", "ListCertificates", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCM ListCertificates error", zap.Error(err))
					return err
				}

				localResponse := &ListCertificatesResponse{}
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(localResponse)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCM ListCertificates decode error", zap.Error(err))
					return err
				}

				response := &ListCertificatesResponseAny{}
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCM ListCertificates decode error", zap.Error(err))
					return err
				}

				if len(response.CertificateSet) == 0 || len(localResponse.CertificateSet) != len(response.CertificateSet) {
					break
				}

				for i := range response.CertificateSet {
					res <- Detail{
						Cert:   response.CertificateSet[i],
						Detail: getCertificateDetail(ctx, cli, localResponse.CertificateSet[i].CertificateId),
					}
				}
				count += len(response.CertificateSet)
				total, _ := strconv.Atoi(*response.PageCount)
				if count >= total {
					break
				}
				request.Page = common.IntPtr(*request.Page + 1)
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Cert.CertificateId",
			ResourceName: "$.Cert.MainDomain",
		},
		Regions: []string{
			"cn-beijing-6",  // 华北1（北京）
			"cn-shanghai-2", // 华东1（上海）
		},
		Dimension: schema.Global,
	}
}

func getCertificateDetail(ctx context.Context, cli *kcm.Client, certId *string) any {
	request := kcm.NewGetCertificateDetailRequest()
	request.CertificateId = certId
	responseStr := cli.GetCertificateDetailWithContext(ctx, request)
	collector.ShowResponse(ctx, "KCM", "GetCertificateDetail", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCM GetCertificateDetail error", zap.Error(err))
		return nil
	}

	response := &GetCertificateDetailResponse{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCM GetCertificateDetail decode error", zap.Error(err))
		return nil
	}

	return response.Certificate
}
