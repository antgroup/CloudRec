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

package dnspod

import (
	"context"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	"go.uber.org/zap"

	"github.com/cloudrec/tencent/collector"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
)

func GetDNSPodResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DNSPod,
		ResourceTypeName:   "DNSPod",
		ResourceGroupType:  constant.NET,
		Desc:               "https://cloud.tencent.com/document/product/302",
		ResourceDetailFunc: ListDNSPodResource,
		RowField: schema.RowField{
			ResourceId:   "$.DomainListItem.DomainId",
			ResourceName: "$.DomainListItem.Name",
		},
		Dimension: schema.Global,
	}
}

type Detail struct {
	DomainListItem *dnspod.DomainListItem
	RecordList     []*dnspod.RecordListItem
}

func ListDNSPodResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).DNSPod
	request := dnspod.NewDescribeDomainFilterListRequest()
	var count, page, limit uint64
	limit = 1000
	request.Limit = common.Uint64Ptr(limit)
	request.Type = common.StringPtr("ALL")
	// request.SortType = common.StringPtr("asc")
	for {
		page++
		request.Offset = common.Uint64Ptr((page - 1) * limit)
		response, err := cli.DescribeDomainFilterList(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDomainFilterList:ERR", zap.Error(err))
			return err
		}
		if response == nil || response.Response == nil || response.Response.DomainList == nil {
			break
		}
		count += uint64(len(response.Response.DomainList))
		if count == 0 {
			break
		}
		for _, item := range response.Response.DomainList {
			res <- &Detail{
				DomainListItem: item,
				RecordList:     getDnsPodRecordList(ctx, cli, item.Name),
			}
			time.Sleep(time.Millisecond * 60)
		}
		if count >= *response.Response.DomainCountInfo.DomainTotal {
			break
		}
	}

	return nil
}
func getDnsPodRecordList(ctx context.Context, cli *dnspod.Client, domain *string) []*dnspod.RecordListItem {
	request := dnspod.NewDescribeRecordFilterListRequest()
	var count, page, limit uint64
	limit = 2000
	request.Limit = common.Uint64Ptr(limit)
	request.Domain = domain
	var recordList = make([]*dnspod.RecordListItem, 0, 2000)
	for {
		page++
		request.Offset = common.Uint64Ptr((page - 1) * limit)
		response, err := cli.DescribeRecordFilterList(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("getDnsPodRecordList:ERR", zap.Error(err))
			return nil
		}
		if response == nil || response.Response == nil || response.Response.RecordList == nil {
			break
		}
		count += uint64(len(response.Response.RecordList))
		if count == 0 {
			break
		}
		recordList = append(recordList, response.Response.RecordList...)
		if count >= *response.Response.RecordCountInfo.TotalCount {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	return recordList
}
