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

package cvm

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/tencent/collector"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	"go.uber.org/zap"
)

func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CVM,
		ResourceTypeName:   "CVM Instance",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://cloud.tencent.com/document/api/213/15728",
		ResourceDetailFunc: ListInstanceResource,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
			Address:      "$.Instance.PublicIpAddresses[0]",
		},
		Regions: []string{
			"ap-shanghai",
			"ap-nanjing",
			"ap-guangzhou",
			"ap-beijing",
			"ap-chengdu",
			"ap-chongqing",
			"ap-hongkong",
			"ap-seoul",
			"ap-tokyo",
			"ap-singapore",
			"ap-bangkok",
			"ap-jakarta",
			"na-siliconvalley",
			"eu-frankfurt",
			"na-ashburn",
			"sa-saopaulo",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Instance *cvm.Instance
}

func ListInstanceResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CVM
	request := cvm.NewDescribeInstancesRequest()
	request.Limit = common.Int64Ptr(100)
	request.Offset = common.Int64Ptr(0)

	var count int64
	for {
		response, err := cli.DescribeInstances(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeInstances error", zap.Error(err))
			return err
		}
		for _, instance := range response.Response.InstanceSet {
			d := &Detail{
				Instance: instance,
			}
			res <- d
		}
		count += int64(len(response.Response.InstanceSet))
		if count >= *response.Response.TotalCount {
			break
		}

		*request.Offset += *request.Limit
	}

	return nil
}
