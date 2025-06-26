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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/cloudrec/alicloud/collector"
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
	Group    ram.Group
	Policies []PolicyDetail
}

func GetGroupDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).RAM

	request := ram.CreateListGroupsRequest()
	request.Scheme = "https"
	for {
		response, err := cli.ListGroups(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListGroups error", zap.Error(err))
			return err
		}
		for _, i := range response.Groups.Group {
			d := GroupDetail{
				Group:    i,
				Policies: listPoliciesForGroup(ctx, cli, i.GroupName),
			}
			res <- d
		}
		if !response.IsTruncated {
			break
		}
		request.Marker = response.Marker
	}
	return nil
}

func listPoliciesForGroup(ctx context.Context, cli *ram.Client, name string) (policies []PolicyDetail) {
	request := ram.CreateListPoliciesForGroupRequest()
	request.Scheme = "https"
	request.GroupName = name
	response, err := cli.ListPoliciesForGroup(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPoliciesForGroup error", zap.Error(err))
		return
	}

	return getPolicyDetails(ctx, cli, response.Policies.Policy, "Group:"+name)
}
