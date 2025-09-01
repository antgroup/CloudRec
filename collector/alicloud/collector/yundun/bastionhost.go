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

package yundun

import (
	"context"
	"github.com/alibabacloud-go/tea/tea"
	yundun_bastionhost20191209 "github.com/alibabacloud-go/yundun-bastionhost-20191209/v2/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetBastionhostResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Bastionhost,
		ResourceTypeName:   "Bastionhost",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "",
		ResourceDetailFunc: GetBastionhostDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.Description",
		},
		Dimension: schema.Regional,
	}
}

type BastionhostDetail struct {
	Instance          *yundun_bastionhost20191209.DescribeInstancesResponseBodyInstances
	InstanceAttribute *yundun_bastionhost20191209.DescribeInstanceAttributeResponseBodyInstanceAttribute
}

func GetBastionhostDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).YUNDUN

	instances, err := listInstances(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list bastionhost instances", zap.Error(err))
		return err
	}

	for _, instance := range instances {
		instanceAttribute := describeInstanceAttribute(ctx, client, instance.InstanceId)
		res <- &BastionhostDetail{
			Instance:          instance,
			InstanceAttribute: instanceAttribute,
		}
	}
	
	return nil
}

func listInstances(ctx context.Context, c *yundun_bastionhost20191209.Client) ([]*yundun_bastionhost20191209.DescribeInstancesResponseBodyInstances, error) {
	var instances []*yundun_bastionhost20191209.DescribeInstancesResponseBodyInstances

	req := &yundun_bastionhost20191209.DescribeInstancesRequest{}
	req.PageSize = tea.Int32(constant.DefaultPageSize)
	req.PageNumber = tea.Int32(constant.DefaultPage)

	count := 0
	for {
		resp, err := c.DescribeInstances(req)
		if err != nil {
			log.CtxLogger(ctx).Error("DescribeInstances error", zap.Error(err))
			return nil, err
		}

		instances = append(instances, resp.Body.Instances...)
		count += len(resp.Body.Instances)

		if count >= int(*resp.Body.TotalCount) || len(resp.Body.Instances) < constant.DefaultPageSize {
			break
		}
		req.PageNumber = tea.Int32(*req.PageNumber + 1)
	}

	return instances, nil
}

func describeInstanceAttribute(ctx context.Context, c *yundun_bastionhost20191209.Client, instanceId *string) *yundun_bastionhost20191209.DescribeInstanceAttributeResponseBodyInstanceAttribute {
	req := &yundun_bastionhost20191209.DescribeInstanceAttributeRequest{
		InstanceId: instanceId,
	}

	resp, err := c.DescribeInstanceAttribute(req)
	if err != nil {
		log.CtxLogger(ctx).Error("DescribeInstanceAttribute error", zap.Error(err), zap.String("instanceId", *instanceId))
		return nil
	}

	return resp.Body.InstanceAttribute
}
