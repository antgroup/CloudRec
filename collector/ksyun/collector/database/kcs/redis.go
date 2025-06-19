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

package kcs

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kcs "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kcs/v20160701"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strconv"
	"strings"
)

type Detail struct {
	Instance       any
	Parameters     []any
	SecurityGroups []any
}

func GetKCSResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KCS,
		ResourceTypeName:  collector.KCS,
		ResourceGroupType: constant.DATABASE,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/0/1022`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KCS
			request := kcs.NewDescribeCacheClustersRequest()
			limit := 100
			request.Limit = common.StringPtr("100")
			request.Offset = common.StringPtr("0")
			count := 0

			for {
				responseStr := cli.DescribeCacheClustersWithContext(ctx, request)
				collector.ShowResponse(ctx, "KCS", "DescribeCacheClusters", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCS DescribeCacheClusters error", zap.Error(err))
					return err
				}

				response := kcs.NewDescribeCacheClustersResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KCS DescribeCacheClustersResponse decode error", zap.Error(err))
					return err
				}
				if len(response.Data.List) == 0 {
					break
				}

				for i := range response.Data.List {
					res <- &Detail{
						Instance:       &response.Data.List[i],
						Parameters:     describeDBInstanceParameters(ctx, cli, response.Data.List[i].CacheId),
						SecurityGroups: describeSecurityGroups(ctx, cli, response.Data.List[i].CacheId),
					}
				}
				count += len(response.Data.List)
				if len(response.Data.List) < limit {
					break
				}
				request.Offset = common.StringPtr(strconv.Itoa(count))
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Instance.cacheId",
			ResourceName: "$.Instance.name",
			Address:      "$.Instance.vip",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"cn-hongkong-2",   // 香港
			"ap-singapore-1",  // 新加坡
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-beijing-fin",  // 华北金融1（北京）
			"cn-northwest-3",  // 西北3区（宁夏）
			"cn-north-vip1",   // 华北专属1区（天津-小米）
		},
		Dimension: schema.Regional,
	}
}

func describeDBInstanceParameters(ctx context.Context, cli *kcs.Client, instanceId *string) (res []any) {
	request := kcs.NewDescribeCacheParametersRequest()
	request.CacheId = instanceId

	responseStr := cli.DescribeCacheParametersWithContext(ctx, request)
	collector.ShowResponse(ctx, "KCS", "DescribeCacheParameters", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("DescribeCacheParameters error", zap.Error(err))
		return nil
	}

	response := kcs.NewDescribeCacheParametersResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("json unmarshal error", zap.Error(err))
		return nil
	}

	for i := range response.Data {
		res = append(res, &response.Data[i])
	}

	return res
}

func describeSecurityGroups(ctx context.Context, cli *kcs.Client, cacheId *string) (res []any) {
	request := kcs.NewDescribeSecurityGroupsRequest()
	request.CacheId = cacheId
	request.Limit = common.IntPtr(100)
	count := 0

	for {
		responseStr := cli.DescribeSecurityGroupsWithContext(ctx, request)
		collector.ShowResponse(ctx, "KCS", "DescribeSecurityGroups", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("DescribeSecurityGroups error", zap.Error(err))
			return res
		}

		response := kcs.NewDescribeSecurityGroupsResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("json unmarshal error", zap.Error(err))
			return res
		}
		if len(response.Data.List) == 0 {
			break
		}

		for i := range response.Data.List {
			sg, _ := describeSecurityGroup(ctx, cli, response.Data.List[i].SecurityGroupId)
			if sg != nil {
				res = append(res, sg)
			}
		}
		count += len(response.Data.List)
		if len(response.Data.List) < *request.Limit {
			break
		}
		request.Offset = common.StringPtr(strconv.Itoa(count))
	}
	return res
}

func describeSecurityGroup(ctx context.Context, cli *kcs.Client, securityGroupId *string) (any, error) {
	request := kcs.NewDescribeSecurityGroupRequest()
	request.SecurityGroupId = securityGroupId

	responseStr := cli.DescribeSecurityGroupWithContext(ctx, request)
	collector.ShowResponse(ctx, "KCS", "DescribeSecurityGroups", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("DescribeSecurityGroups error", zap.Error(err))
		return nil, err
	}

	response := kcs.NewDescribeSecurityGroupResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("json unmarshal error", zap.Error(err))
		return nil, err
	}

	return &response.Data, nil
}
