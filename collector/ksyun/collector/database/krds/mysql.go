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

package krds

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	krds "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/krds/v20160701"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type Detail struct {
	Instance       any
	Parameters     any
	SecurityGroups []any
}

func GetKRDSResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KRDS,
		ResourceTypeName:  collector.KRDS,
		ResourceGroupType: constant.DATABASE,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/42/1021`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KRDS
			request := krds.NewDescribeDBInstancesRequest()
			request.MaxRecords = common.IntPtr(100)
			request.Marker = common.IntPtr(0)
			count := 0

			for {
				responseStr := cli.DescribeDBInstancesWithContext(ctx, request)
				collector.ShowResponse(ctx, "KRDS", "DescribeDBInstances", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KRDS DescribeDBInstances error", zap.Error(err))
					return err
				}

				response := krds.NewDescribeDBInstancesResponse()
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KRDS DescribeDBInstancesResponse decode error", zap.Error(err))
					return err
				}
				if len(response.Data.Instances) == 0 {
					break
				}

				for i := range response.Data.Instances {
					item := &response.Data.Instances[i]
					res <- &Detail{
						Instance:       item,
						Parameters:     describeDBInstanceParameters(ctx, cli, item.DBInstanceIdentifier),
						SecurityGroups: describeSecurityGroups(ctx, cli, item.SecurityGroupId),
					}
				}
				count += len(response.Data.Instances)
				if count >= *response.Data.TotalCount {
					break
				}
				request.Marker = response.Data.Marker
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Instance.DBInstanceIdentifier",
			ResourceName: "$.Instance.DBInstanceName",
			Address:      "$.Instance.Vip",
		},
		Regions: []string{
			"cn-beijing-6",   // 华北1（北京）
			"cn-shanghai-2",  // 华东1（上海）
			"cn-guangzhou-1", // 华南1（广州）
			"cn-hongkong-2",  // 香港
			"eu-east-1",      // 俄罗斯（莫斯科）
			"cn-taipei-1",    // 台北
			"cn-beijing-fin", // 华北金融1（北京）
		},
		Dimension: schema.Regional,
	}
}

func describeDBInstanceParameters(ctx context.Context, cli *krds.Client, instanceId *string) any {
	request := krds.NewDescribeDBInstanceParametersRequest()
	request.DBInstanceIdentifier = instanceId

	responseStr := cli.DescribeDBInstanceParametersWithContext(ctx, request)
	collector.ShowResponse(ctx, "KRDS", "DescribeDBInstanceParameters", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("DescribeDBInstanceParameters error", zap.Error(err))
		return nil
	}

	response := krds.NewDescribeDBInstanceParametersResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("json unmarshal error", zap.Error(err))
		return nil
	}

	return &response.Data
}

func describeSecurityGroups(ctx context.Context, cli *krds.Client, securityGroupId *string) (res []any) {
	request := krds.NewDescribeSecurityGroupRequest()
	request.SecurityGroupId = securityGroupId

	responseStr := cli.DescribeSecurityGroupWithContext(ctx, request)
	collector.ShowResponse(ctx, "KRDS", "DescribeSecurityGroup", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("DescribeSecurityGroup error", zap.Error(err))
		return res
	}

	response := krds.NewDescribeSecurityGroupResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("json unmarshal error", zap.Error(err))
		return res
	}

	for i := range response.Data.SecurityGroups {
		res = append(res, &response.Data.SecurityGroups[i])
	}

	return res
}
