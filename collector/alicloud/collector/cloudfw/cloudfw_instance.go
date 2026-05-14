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

package cloudfw

import (
	"context"
	cloudfw20171207 "github.com/alibabacloud-go/cloudfw-20171207/v8/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"strconv"
	"time"
)

func GetCloudFWResource() schema.Resource {
	return schema.Resource{
		ResourceType:                 collector.Cloudfw,
		ResourceTypeName:             "Cloud Firewall Instance",
		ResourceGroupType:            constant.SECURITY,
		Desc:                         `https://api.aliyun.com/product/Cloudfw`,
		ResourceDetailFuncWithCancel: GetInstanceDetail,
		Dimension:                    schema.Global,
	}
}

func GetInstanceDetail(ctx context.Context, cancel context.CancelFunc, service schema.ServiceInterface, res chan<- any) error {

	cli := service.(*collector.Services).Cloudfw
	direction := []string{"in", "out"}
	err := collectControlPolicies(ctx, direction, 50, func(d string, page int, size int) ([]*cloudfw20171207.DescribeControlPolicyResponseBodyPolicys, int, error) {
		req := &cloudfw20171207.DescribeControlPolicyRequest{}
		req.CurrentPage = tea.String(strconv.Itoa(page))
		req.PageSize = tea.String(strconv.Itoa(size))
		req.Direction = tea.String(d)
		resp, err := cli.DescribeControlPolicyWithOptions(req, collector.RuntimeObject)
		if err != nil {
			return nil, 0, err
		}
		if resp == nil || resp.Body == nil {
			return nil, 0, nil
		}
		totalCount := 0
		if resp.Body.TotalCount != nil {
			totalCount, err = strconv.Atoi(*resp.Body.TotalCount)
			if err != nil {
				return nil, 0, err
			}
		}
		return resp.Body.Policys, totalCount, nil
	}, func(policy *cloudfw20171207.DescribeControlPolicyResponseBodyPolicys) {
		res <- Detail{
			Policy: policy,
		}
	}, time.Sleep)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeControlPolicyWithOptions error", zap.Error(err))
		cancel()
		return err
	}

	return nil
}

type controlPolicyFetcher func(direction string, page int, size int) ([]*cloudfw20171207.DescribeControlPolicyResponseBodyPolicys, int, error)

func collectControlPolicies(ctx context.Context, directions []string, pageSize int, fetch controlPolicyFetcher, emit func(*cloudfw20171207.DescribeControlPolicyResponseBodyPolicys), sleep func(time.Duration)) error {
	if pageSize <= 0 {
		pageSize = 50
	}
	if sleep == nil {
		sleep = func(time.Duration) {}
	}
	for _, d := range directions {
		page := 1
		count := 0
		for {
			select {
			case <-ctx.Done():
				log.CtxLogger(ctx).Warn("time out !!! please check your code")
				return nil
			default:
			}

			policies, totalCount, err := fetch(d, page, pageSize)
			if err != nil {
				return err
			}
			count += len(policies)
			for _, policy := range policies {
				emit(policy)
			}
			if totalCount <= 0 || count >= totalCount || len(policies) == 0 {
				break
			}
			page += 1
			sleep(1 * time.Second)
		}
	}
	return nil
}

type Detail struct {
	Policy *cloudfw20171207.DescribeControlPolicyResponseBodyPolicys
}
