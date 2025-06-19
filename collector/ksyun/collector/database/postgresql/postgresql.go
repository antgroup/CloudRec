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

package postgresql

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	postgresql "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/postgresql/v20181225"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type Detail struct {
	Instance       any
	Parameters     any
	SecurityGroups []any
}

func GetPostgreSQLResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.PostgreSQL,
		ResourceTypeName:  collector.PostgreSQL,
		ResourceGroupType: constant.DATABASE,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/120/1223`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).PostgreSQL
			request := postgresql.NewDescribeDBInstancesRequest()
			maxRecords := 100
			request.MaxRecords = common.IntPtr(maxRecords)
			request.Marker = common.IntPtr(0)
			count := 0

			for {
				responseStr := cli.DescribeDBInstancesWithContext(ctx, request)
				collector.ShowResponse(ctx, "PostgreSQL", "DescribeDBInstances", responseStr)
				err := collector.CheckError(responseStr)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("PostgreSQL DescribeDBInstances error", zap.Error(err))
					return err
				}

				response := &DescribeDBInstancesResponse{}
				err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
				if err != nil {
					log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("PostgreSQL DescribeDBInstancesResponse decode error", zap.Error(err))
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
				if len(response.Data.Instances) < maxRecords {
					break
				}
				request.Marker = common.IntPtr(count)
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

func describeDBInstanceParameters(ctx context.Context, cli *postgresql.Client, instanceId *string) any {
	request := postgresql.NewDescribeDBInstanceParametersRequest()
	request.DBInstanceIdentifier = instanceId

	responseStr := cli.DescribeDBInstanceParametersWithContext(ctx, request)
	collector.ShowResponse(ctx, "PostgreSQL", "DescribeDBInstanceParameters", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("PostgreSQL DescribeDBInstanceParameters error", zap.Error(err))
		return nil
	}

	response := &DescribeDBInstanceParametersResponse{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("PostgreSQL DescribeDBInstanceParametersResponse decode error", zap.Error(err))
		return nil
	}

	return &response.Data
}

func describeSecurityGroups(ctx context.Context, cli *postgresql.Client, securityGroupId *string) (res []any) {
	request := postgresql.NewDescribeSecurityGroupRequest()
	request.SecurityGroupId = securityGroupId

	responseStr := cli.DescribeSecurityGroupWithContext(ctx, request)
	collector.ShowResponse(ctx, "PostgreSQL", "DescribeSecurityGroup", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("PostgreSQL DescribeSecurityGroup error", zap.Error(err))
		return res
	}

	response := postgresql.NewDescribeSecurityGroupResponse()
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("PostgreSQL DescribeSecurityGroupResponse decode error", zap.Error(err))
		return res
	}

	for i := range response.Data.SecurityGroups {
		res = append(res, &response.Data.SecurityGroups[i])
	}

	return res
}
