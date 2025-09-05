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
	cloudfw20171207 "github.com/alibabacloud-go/cloudfw-20171207/v7/client"
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
	for _, d := range direction {
		page := 1
		size := 50
		count := 0
		for {
			select {
			case <-ctx.Done():
				log.CtxLogger(ctx).Warn("time out !!! please check your code")
				return nil
			default:
				req := &cloudfw20171207.DescribeControlPolicyRequest{}
				req.CurrentPage = tea.String(strconv.Itoa(page))
				req.PageSize = tea.String(strconv.Itoa(size))
				req.Direction = tea.String(d)
				resp, err := cli.DescribeControlPolicyWithOptions(req, collector.RuntimeObject)
				if err != nil {
					log.CtxLogger(ctx).Warn("DescribeControlPolicyWithOptions error", zap.Error(err))
					cancel()
					return err
				}

				bd := resp.Body
				count += len(bd.Policys)
				req.PageSize = tea.String(strconv.Itoa(size))
				for i := 0; i < len(bd.Policys); i++ {
					res <- Detail{
						Policy: bd.Policys[i],
					}
				}

				if bd.TotalCount == nil || strconv.Itoa(count) >= *bd.TotalCount {
					cancel()
					return nil
				}

				page += 1
				req.CurrentPage = tea.String(strconv.Itoa(page))
				time.Sleep(1 * time.Second)
			}
		}
	}

	return nil
}

type Detail struct {
	Policy *cloudfw20171207.DescribeControlPolicyResponseBodyPolicys
}
