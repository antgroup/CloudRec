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

package cloudcenter

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	sas20181203 "github.com/alibabacloud-go/sas-20181203/v3/client"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

type SasDetail struct {
	CloudAccountId string
	AuthSummary    *sas20181203.GetAuthSummaryResponseBody
}

func GetSasConfigResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SasConfig,
		ResourceTypeName:   "SAS Config",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/Sas`,
		ResourceDetailFunc: GetSasRootDetail,
		RowField: schema.RowField{
			ResourceId:   "$.CloudAccountId",
			ResourceName: "$.CloudAccountId",
		},
		Regions:   []string{"cn-shanghai", "ap-southeast-1"},
		Dimension: schema.Regional,
	}
}

func GetSasRootDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Sas

	response, err := cli.GetAuthSummary()
	if err != nil {
		log.CtxLogger(ctx).Error("GetAuthSummary error", zap.Error(err))
		return err
	}

	d := &SasDetail{
		CloudAccountId: log.GetCloudAccountId(ctx),
		AuthSummary:    response.Body,
	}

	res <- d

	return nil
}
