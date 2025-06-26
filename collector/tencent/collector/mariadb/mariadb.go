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

package mariadb

import (
	"context"

	"github.com/cloudrec/tencent/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	mariadb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/mariadb/v20170312"
	"go.uber.org/zap"
)

func GetMariaDBResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MariaDB,
		ResourceTypeName:   "MariaDB",
		ResourceGroupType:  constant.DATABASE,
		Desc:               "https://cloud.tencent.com/document/api/237/16184",
		ResourceDetailFunc: ListMariaDBResource,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.InstanceId",
			ResourceName: "$.DBInstance.InstanceName",
			Address:      "$.DBInstance.WanVip",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	DBInstance mariadb.DBInstance
}

func ListMariaDBResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).MariaDB

	request := mariadb.NewDescribeDBInstancesRequest()
	request.Limit = common.Int64Ptr(100)
	request.Offset = common.Int64Ptr(0)

	var count uint64
	for {
		response, err := cli.DescribeDBInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeDBInstances error", zap.Error(err))
			return err
		}

		for _, instance := range response.Response.Instances {
			d := &Detail{
				DBInstance: *instance,
			}
			res <- d
		}

		count += uint64(len(response.Response.Instances))
		if count >= *response.Response.TotalCount {
			break
		}

		*request.Offset += *request.Limit
	}

	return nil
}
