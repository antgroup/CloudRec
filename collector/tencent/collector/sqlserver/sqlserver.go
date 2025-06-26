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

package sqlserver

import (
	"context"

	"github.com/cloudrec/tencent/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	sqlserver "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sqlserver/v20180328"
	"go.uber.org/zap"
)

func GetDBInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SQLServer,
		ResourceTypeName:   "SQL Server",
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://cloud.tencent.com/document/api/238/19969",
		ResourceDetailFunc: ListDBInstanceResource,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.InstanceId",
			ResourceName: "$.DBInstance.Name",
			Address:      "$.DBInstance.Vip",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	DBInstance sqlserver.DBInstance
}

func ListDBInstanceResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).SQLServer

	request := sqlserver.NewDescribeDBInstancesRequest()
	request.Limit = common.Int64Ptr(100)
	request.Offset = common.Int64Ptr(0)

	var count int64
	for {
		response, err := cli.DescribeDBInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDBInstances error", zap.Error(err))
			return err
		}

		for _, instance := range response.Response.DBInstances {
			d := &Detail{
				DBInstance: *instance,
			}
			res <- d
		}

		count += int64(len(response.Response.DBInstances))
		if count >= *response.Response.TotalCount {
			break
		}

		*request.Offset += *request.Limit
	}

	return nil
}
