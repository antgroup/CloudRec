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

package hitsdb

import (
	"context"
	hitsdb20200615 "github.com/alibabacloud-go/hitsdb-20200615/v5/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetLindormResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Lindorm,
		ResourceTypeName:   collector.Lindorm,
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://api.aliyun.com/product/hitsdb",
		ResourceDetailFunc: GetLindormDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.InstanceId.InstanceAlias",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"ap-southeast-3",
			"ap-northeast-1",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
		},
		Dimension: schema.Regional,
	}
}

type LindormDetail struct {
	Instance            *hitsdb20200615.GetLindormInstanceListResponseBodyInstanceList
	EngineList          []*hitsdb20200615.GetLindormInstanceEngineListResponseBodyEngineList
	InstanceIpWhiteList LindormInstanceIpWhiteList
}
type LindormInstanceIpWhiteList struct {
	IpList    []*string
	GroupList []*hitsdb20200615.GetInstanceIpWhiteListResponseBodyGroupList
}

func GetLindormDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).HITSDB

	getLindormInstanceListRequest := &hitsdb20200615.GetLindormInstanceListRequest{}

	var count, pageNum int32
	for {
		getLindormInstanceListResponse, err := client.GetLindormInstanceList(getLindormInstanceListRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("GetLindormInstanceList error", zap.Error(err))
			return err
		}
		for _, i := range getLindormInstanceListResponse.Body.InstanceList {
			d := &LindormDetail{
				Instance:            i,
				EngineList:          getEngineList(ctx, client, i.InstanceId),
				InstanceIpWhiteList: getInstanceIpWhiteList(ctx, client, i.InstanceId),
			}
			res <- d
		}
		count += *getLindormInstanceListResponse.Body.PageSize
		if count >= *getLindormInstanceListResponse.Body.Total || getLindormInstanceListResponse.Body.InstanceList == nil {
			break
		}
		pageNum = *getLindormInstanceListResponse.Body.PageNumber + 1
		getLindormInstanceListRequest.PageNumber = &pageNum
	}

	return nil
}

func getInstanceIpWhiteList(ctx context.Context, client *hitsdb20200615.Client, id *string) LindormInstanceIpWhiteList {
	request := &hitsdb20200615.GetInstanceIpWhiteListRequest{
		InstanceId: id,
	}
	response, err := client.GetInstanceIpWhiteList(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetInstanceIpWhiteList error", zap.Error(err))
		return LindormInstanceIpWhiteList{}
	}
	return LindormInstanceIpWhiteList{
		IpList:    response.Body.IpList,
		GroupList: response.Body.GroupList,
	}
}

func getEngineList(ctx context.Context, client *hitsdb20200615.Client, id *string) []*hitsdb20200615.GetLindormInstanceEngineListResponseBodyEngineList {
	request := &hitsdb20200615.GetLindormInstanceEngineListRequest{
		InstanceId: id,
	}
	response, err := client.GetLindormInstanceEngineList(request)
	if err != nil {
		return nil
	}
	if response.Body.AccessDeniedDetail != nil {
		log.CtxLogger(ctx).Warn("GetLindormInstanceEngineList error", zap.Error(err))
		return nil
	}

	return response.Body.EngineList
}
