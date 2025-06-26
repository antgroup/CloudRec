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

package postgres

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/tencent/collector"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	postgres "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/postgres/v20170312"
	"go.uber.org/zap"
)

func GetPostgresResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.PostgreSQL,
		ResourceTypeName:   "PostgreSQL",
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://cloud.tencent.com/document/api/409/16773",
		ResourceDetailFunc: ListPostgresResource,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.DBInstanceId",
			ResourceName: "$.DBInstance.DBInstanceName",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	DBInstance postgres.DBInstance
}

func ListPostgresResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).PostgreSQL

	request := postgres.NewDescribeDBInstancesRequest()
	request.Limit = common.Uint64Ptr(100)
	request.Offset = common.Uint64Ptr(0)

	var count uint64
	for {
		response, err := cli.DescribeDBInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDBInstances error", zap.Error(err))
			return err
		}

		for _, instance := range response.Response.DBInstanceSet {
			d := &Detail{
				DBInstance: *instance,
			}
			res <- d
		}

		count += uint64(len(response.Response.DBInstanceSet))
		if count >= *response.Response.TotalCount {
			break
		}

		*request.Offset += *request.Limit
	}

	return nil
}
