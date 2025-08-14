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

package tablestore

import (
	"context"
	tablestore "github.com/alibabacloud-go/tablestore-20201209/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetTablestoreResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Tablestore,
		ResourceTypeName:   "Tablestore",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://api.aliyun.com/product/Tablestore",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.InstanceInfo.InstanceName",
			ResourceName: "$.InstanceInfo.InstanceName",
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
			"cn-guangzhou",
			"ap-southeast-6",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-shanghai-finance-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Tablestore

	listInstancesRequest := &tablestore.ListInstancesRequest{}
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)

	instances, err := cli.ListInstancesWithOptions(listInstancesRequest, headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListInstancesWithOptions error", zap.Error(err))
		return err
	}

	if len(instances.Body.Instances) == 0 {
		return nil
	}

	for _, instance := range instances.Body.Instances {
		res <- Detail{
			InstanceInfo: describeInstanceDetail(ctx, cli, instance.InstanceName),
		}
	}
	return nil
}

type Detail struct {
	InstanceInfo *tablestore.GetInstanceResponseBody
}

func describeInstanceDetail(ctx context.Context, cli *tablestore.Client, instanceName *string) *tablestore.GetInstanceResponseBody {
	getInstanceRequest := &tablestore.GetInstanceRequest{
		InstanceName: instanceName,
	}
	runtime := &util.RuntimeOptions{}
	headers := make(map[string]*string)

	result, err := cli.GetInstanceWithOptions(getInstanceRequest, headers, runtime)
	if err != nil {
		log.CtxLogger(ctx).Error("GetInstanceWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body
}
