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

package cloudcenter

import (
	"context"
	sas20181203 "github.com/alibabacloud-go/sas-20181203/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

type Detail struct {
	Instance *sas20181203.DescribeCloudCenterInstancesResponseBodyInstances
}

func GetCloudCenterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Sas,
		ResourceTypeName:   "SAS Instance",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://api.aliyun.com/product/Sas`,
		ResourceDetailFunc: GetSasInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
			Address:      "$.Instance.InternetIp",
		},
		Regions:   []string{"cn-shanghai", "ap-southeast-1"},
		Dimension: schema.Regional,
	}
}

func GetSasInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).Sas

	machineTypes := []string{"ecs"}
	for _, machineType := range machineTypes {
		var page int32 = 1
		var count = 0

		request := &sas20181203.DescribeCloudCenterInstancesRequest{}
		request.CurrentPage = tea.Int32(page)
		request.PageSize = tea.Int32(100)
		request.MachineTypes = tea.String(machineType)
		for {
			response, err := cli.DescribeCloudCenterInstancesWithOptions(request, collector.RuntimeObject)
			if err != nil {
				log.CtxLogger(ctx).Error("DescribeCloudCenterInstancesWithOptions error", zap.Error(err))
				return err
			}
			for _, i := range response.Body.Instances {
				res <- &Detail{
					Instance: i,
				}
			}
			count += len(response.Body.Instances)
			if count >= int(*response.Body.PageInfo.TotalCount) || len(response.Body.Instances) == 0 {
				break
			}
			page += 1
			request.CurrentPage = tea.Int32(page)
		}
	}
	return nil
}
