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

package cloudfw

import (
	"context"
	cloudfw20171207 "github.com/alibabacloud-go/cloudfw-20171207/v8/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetCloudFWConfigResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudfwConfig,
		ResourceTypeName:   "Cloud Firewall Config",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/Cloudfw`,
		ResourceDetailFunc: GetDetail,
		Dimension:          schema.Global,
		RowField: schema.RowField{
			ResourceId:   "$.CloudfwVersionInfo.InstanceId",
			ResourceName: "$.CloudfwVersionInfo.InstanceId",
		},
	}
}

func GetDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Cloudfw
	req := &cloudfw20171207.DescribeUserBuyVersionRequest{}
	info, err := cli.DescribeUserBuyVersion(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeUserBuyVersion Error", zap.Error(err))
		return err
	}

	res <- &CloudfwConfigDetail{
		CloudfwVersionInfo: info.Body,
		LogStoreInfo:       describeLogStoreInfo(ctx, cli),
	}

	return nil
}

type CloudfwConfigDetail struct {
	CloudfwVersionInfo *cloudfw20171207.DescribeUserBuyVersionResponseBody
	LogStoreInfo       *cloudfw20171207.DescribeLogStoreInfoResponseBody
}

func describeLogStoreInfo(ctx context.Context, cli *cloudfw20171207.Client) *cloudfw20171207.DescribeLogStoreInfoResponseBody {
	resp, err := cli.DescribeLogStoreInfo()
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLogStoreInfo Error", zap.Error(err))
		return nil
	}

	return resp.Body
}
