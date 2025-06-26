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

package vpc

import (
	"context"

	"github.com/cloudrec/tencent/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
	"go.uber.org/zap"
)

func GetSecurityGroupResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SecurityGroup,
		ResourceTypeName:   "Security Group",
		ResourceGroupType:  constant.NET,
		Desc:               "https://cloud.tencent.com/document/product/215/20089",
		ResourceDetailFunc: ListSecurityGroupResource,
		RowField: schema.RowField{
			ResourceId:   "$.SecurityGroup.SecurityGroupId",
			ResourceName: "$.SecurityGroup.SecurityGroupName",
		},
		Regions:   []string{},
		Dimension: schema.Regional,
	}
}

type SecurityGroupDetail struct {
	SecurityGroup          vpc.SecurityGroup
	SecurityGroupPolicySet vpc.SecurityGroupPolicySet
}

func ListSecurityGroupResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPC

	request := vpc.NewDescribeSecurityGroupsRequest()
	request.Limit = common.StringPtr("100")
	request.Offset = common.StringPtr("0")

	var count uint64
	for {
		response, err := cli.DescribeSecurityGroups(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeSecurityGroups error", zap.Error(err))
			return err
		}

		for _, sgset := range response.Response.SecurityGroupSet {
			d := &SecurityGroupDetail{
				SecurityGroup:          *sgset,
				SecurityGroupPolicySet: describeSecurityGroupPolicies(cli, sgset.SecurityGroupId),
			}
			res <- d
		}

		count += uint64(len(response.Response.SecurityGroupSet))
		if count >= *response.Response.TotalCount {
			break
		}

		*request.Offset += *request.Limit
	}

	return nil
}

func describeSecurityGroupPolicies(cli *vpc.Client, securityGroupId *string) (SecurityGroupPolicySet vpc.SecurityGroupPolicySet) {

	request := vpc.NewDescribeSecurityGroupPoliciesRequest()
	request.SecurityGroupId = securityGroupId

	response, err := cli.DescribeSecurityGroupPolicies(request)
	if err != nil {
		return
	}
	return *response.Response.SecurityGroupPolicySet
}
