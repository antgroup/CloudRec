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

package ims

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/alibabacloud-go/ims-20190815/v4/client"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetAccountResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Account,
		ResourceTypeName:   collector.Account,
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://api.aliyun.com/product/Ims`,
		ResourceDetailFunc: GetAccountDetail,
		RowField: schema.RowField{
			ResourceId:   "", // Account ID on the server side would be the id
			ResourceName: "", // Account ID on the server side would be the name
		},
		Regions:   []string{"cn-hangzhou"},
		Dimension: schema.Global,
	}
}

type AccountDetail struct {
	AccountSummary *client.GetAccountSummaryResponseBodySummaryMap

	AccountSecurityPracticeReport *client.GetAccountSecurityPracticeReportResponseBodyAccountSecurityPracticeInfo

	PasswordPolicy *client.GetPasswordPolicyResponseBodyPasswordPolicy

	UserSsoSettings *client.GetUserSsoSettingsResponseBodyUserSsoSettings

	SecurityPreference *client.GetSecurityPreferenceResponseBodySecurityPreference
}

func GetAccountDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).IMS

	getAccountSummaryResponse, err := cli.GetAccountSummary()
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccountSummary error", zap.Error(err))
		return err
	}
	getAccountSecurityPracticeReportResponse, err := cli.GetAccountSecurityPracticeReport()
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccountSecurityPracticeReport error", zap.Error(err))
		return err
	}

	request := ram.CreateGetPasswordPolicyRequest()
	request.Scheme = "https"
	getPasswordPolicyResp, err := cli.GetPasswordPolicy()
	if err != nil {
		log.CtxLogger(ctx).Warn("GetPasswordPolicy error", zap.Error(err))
		return err
	}

	getUserSsoSettingsResp, err := cli.GetUserSsoSettingsWithOptions(collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetUserSsoSettingsWithOptions error", zap.Error(err))
		return err
	}

	getSecurityPreferenceResp, err := cli.GetSecurityPreference()
	if err != nil {
		log.CtxLogger(ctx).Warn("GetSecurityPreference error", zap.Error(err))
		return err
	}

	res <- AccountDetail{

		AccountSummary: getAccountSummaryResponse.Body.SummaryMap,

		AccountSecurityPracticeReport: getAccountSecurityPracticeReportResponse.Body.AccountSecurityPracticeInfo,

		PasswordPolicy: getPasswordPolicyResp.Body.PasswordPolicy,

		UserSsoSettings: getUserSsoSettingsResp.Body.UserSsoSettings,

		SecurityPreference: getSecurityPreferenceResp.Body.SecurityPreference,
	}

	return nil
}
