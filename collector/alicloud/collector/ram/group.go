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

package ram

import (
	"context"
	ram20150501 "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.RMAGroup,
		ResourceTypeName:   collector.RMAGroup,
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://api.aliyun.com/product/Ram`,
		ResourceDetailFunc: GetGroupDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Group.GroupId",
			ResourceName: "$.Group.GroupName",
		},
		Dimension: schema.Global,
	}
}

type GroupDetail struct {
	Group    *ram20150501.ListGroupsResponseBodyGroupsGroup
	Policies []PolicyDetail
}

func GetGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RAM

	request := &ram20150501.ListGroupsRequest{}
	for {
		response, err := cli.ListGroupsWithOptions(request, collector.RuntimeObject)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListGroups error", zap.Error(err))
			return err
		}
		if response.Body.Groups != nil && response.Body.Groups.Group != nil {
			for _, i := range response.Body.Groups.Group {
				d := GroupDetail{
					Group:    i,
					Policies: listPoliciesForGroup(ctx, cli, tea.StringValue(i.GroupName)),
				}
				res <- d
			}
		}
		if response.Body.IsTruncated == nil || !tea.BoolValue(response.Body.IsTruncated) {
			break
		}
		request.Marker = response.Body.Marker
	}
	return nil
}

func listPoliciesForGroup(ctx context.Context, cli *ram20150501.Client, name string) (policies []PolicyDetail) {
	request := &ram20150501.ListPoliciesForGroupRequest{
		GroupName: tea.String(name),
	}
	response, err := cli.ListPoliciesForGroupWithOptions(request, collector.RuntimeObject)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForGroup error", zap.Error(err))
		return
	}

	return getPolicyDetailsForGroup(ctx, cli, response.Body.Policies.Policy, "Group:"+name)
}

func getPolicyDetailsForGroup(ctx context.Context, cli *ram20150501.Client, policy []*ram20150501.ListPoliciesForGroupResponseBodyPoliciesPolicy, source string) (policies []PolicyDetail) {
	for i := 0; i < len(policy); i++ {
		if policy[i].PolicyName != nil && policy[i].PolicyType != nil {
			r := &ram20150501.GetPolicyRequest{
				PolicyName: policy[i].PolicyName,
				PolicyType: policy[i].PolicyType,
			}
			resp, err := cli.GetPolicyWithOptions(r, collector.RuntimeObject)
			if err != nil {
				log.CtxLogger(ctx).Warn("GetPolicy error", zap.Error(err))
				continue
			}
			p := PolicyDetail{
				Policy:               resp.Body.Policy,
				DefaultPolicyVersion: resp.Body.DefaultPolicyVersion,
				Source:               source,
			}
			policies = append(policies, p)
		}
	}
	return policies
}
