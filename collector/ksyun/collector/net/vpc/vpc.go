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

package vpc

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	vpc "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/vpc/v20160304"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type KSyunVPCDetail struct {
	VPC  any
	Acls []any
}

func GetVPCResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.VPC,
		ResourceTypeName:  collector.VPC,
		ResourceGroupType: constant.NET,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/0/1014`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).VPC
			request := vpc.NewDescribeVpcsRequest()
			request.MaxResults = common.IntPtr(100)

			for {
				responseStr := cli.DescribeVpcsWithContext(ctx, request)
				collector.ShowResponse(ctx, "VPC", "DescribeVpcs", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("VPC DescribeVpcs error", zap.Error(err))
					return err
				}

				response := vpc.NewDescribeVpcsResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("VPC DescribeVpcsResponse decode error", zap.Error(err))
					return err
				}
				if len(response.VpcSet) == 0 {
					break
				}

				for i := range response.VpcSet {
					res <- &KSyunVPCDetail{
						VPC:  &response.VpcSet[i],
						Acls: describeNetworkAcls(ctx, cli, response.VpcSet[i].VpcId),
					}
				}
				if response.NextToken == nil || len(response.VpcSet) < *request.MaxResults {
					break
				}
				request.NextToken = response.NextToken
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.VPC.VpcId",
			ResourceName: "$.VPC.VpcName",
		},
		Regions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"cn-central-1",    // 华中1（武汉）
			"cn-hongkong-2",   // 香港
			"ap-singapore-1",  // 新加坡
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-beijing-fin",  // 华北金融1（北京）
			"cn-southwest-1",  // 西南1（重庆）
			"cn-northwest-1",  // 西北1（庆阳）
			"cn-northwest-2",  // 西北2区（庆阳）
			"cn-northwest-3",  // 西北3区（宁夏）
			"cn-north-vip1",   // 华北专属1区（天津-小米）
			"cn-ningbo-1",     // 华东2（宁波）
			"cn-northwest-4",  // 西北4（海东）
		},
		Dimension: schema.Regional,
	}
}

func describeNetworkAcls(ctx context.Context, cli *vpc.Client, vpcId *string) (res []any) {
	request := vpc.NewDescribeNetworkAclsRequest()
	request.Filter = []*vpc.DescribeNetworkAclsFilter{
		1: {
			Name:  common.StringPtr("vpc-id"),
			Value: []*string{1: vpcId},
		},
	}
	request.MaxResults = common.IntPtr(100)

	for {
		responseStr := cli.DescribeNetworkAclsWithContext(ctx, request)
		collector.ShowResponse(ctx, "VPC", "DescribeNetworkAcls", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("VPC DescribeNetworkAcls error", zap.Error(err))
			return nil
		}

		response := vpc.NewDescribeNetworkAclsResponse()
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("VPC DescribeNetworkAclsResponse decode error", zap.Error(err))
			return nil
		}
		if len(response.NetworkAclSet) == 0 {
			break
		}

		for i := range response.NetworkAclSet {
			res = append(res, &response.NetworkAclSet[i])
		}

		if response.NextToken == nil || len(response.NetworkAclSet) < *request.MaxResults {
			break
		}
		request.NextToken = response.NextToken
	}

	return res
}
