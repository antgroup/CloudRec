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

package cam

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/tencent/collector"
	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"go.uber.org/zap"
	"time"
)

func GetUserResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CAMUser,
		ResourceTypeName:   "CAM User",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               "https://cloud.tencent.com/document/product/598",
		ResourceDetailFunc: ListUserResource,
		RowField: schema.RowField{
			ResourceId:   "$.SubAccountInfo.Uid",
			ResourceName: "$.SubAccountInfo.Name",
		},
		Dimension: schema.Global,
	}
}

type UserDetail struct {
	SubAccountInfo           cam.SubAccountInfo
	AttachedUserPolicyDetail []AttachedUserPolicyDetail
	GroupInfo                []cam.GroupInfo
	AccessKeys               []*cam.AccessKey
}

type AttachedUserPolicyDetail struct {
	AttachedUserPolicy cam.AttachPolicyInfo
	PolicyDocument     *string
}

func ListUserResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CAM

	request := cam.NewListUsersRequest()

	response, err := cli.ListUsers(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListUsers error", zap.Error(err))
		return err
	}

	for _, data := range response.Response.Data {
		d := &UserDetail{
			SubAccountInfo:           *data,
			AttachedUserPolicyDetail: listAttachedUserPolicies(ctx, cli, data.Uin),
			GroupInfo:                listGroupsForUser(ctx, cli, data.Uin),
			AccessKeys:               listAccessKeys(ctx, cli, data.Uin),
		}

		res <- d
	}

	return nil
}

func listAttachedUserPolicies(ctx context.Context, cli *cam.Client, uin *uint64) (attachedUserPolicyDetails []AttachedUserPolicyDetail) {

	request := cam.NewListAttachedUserPoliciesRequest()

	// The maximum value of Rp is not documented,
	// trying via the cli,
	// we found out that the maximum value is 200.
	request.Rp = common.Uint64Ptr(200)
	request.TargetUin = uin

	var count uint64
	var attachPolicyInfo []cam.AttachPolicyInfo
	for {
		response, err := cli.ListAttachedUserPolicies(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListAttachedUserPolicies error", zap.Error(err))
			break
		}

		// So we just need to have a good sleep
		time.Sleep(1000 * time.Millisecond)

		for _, policyInfo := range response.Response.List {
			attachPolicyInfo = append(attachPolicyInfo, *policyInfo)
		}
		count += uint64(len(response.Response.List))
		if count == *response.Response.TotalNum {
			break
		}
		*request.Page = *request.Page + 1

	}

	for _, policy := range attachPolicyInfo {
		attachedUserPolicyDetails = append(attachedUserPolicyDetails, AttachedUserPolicyDetail{
			AttachedUserPolicy: policy,
			PolicyDocument:     getPolicy(ctx, cli, policy.PolicyId),
		})
	}

	return attachedUserPolicyDetails
}

func getPolicy(ctx context.Context, cli *cam.Client, id *uint64) *string {
	request := cam.NewGetPolicyRequest()
	request.PolicyId = id
	response, err := cli.GetPolicy(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetPolicy error", zap.Error(err))
		return nil
	}
	return response.Response.PolicyDocument
}

func listGroupsForUser(ctx context.Context, cli *cam.Client, uin *uint64) (groupInfos []cam.GroupInfo) {
	request := cam.NewListGroupsForUserRequest()

	// The maximum value of Rp is not documented,
	// trying via the cli,
	// we found out that the maximum value is 1000.
	request.Rp = common.Uint64Ptr(1000)
	request.SubUin = uin

	var count uint64
	for {
		response, err := cli.ListGroupsForUser(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListGroupsForUser error", zap.Error(err))
			break
		}

		// So we just need to have a good sleep
		time.Sleep(1000 * time.Millisecond)

		for _, groupInfo := range response.Response.GroupInfo {
			groupInfos = append(groupInfos, *groupInfo)
		}
		count += uint64(len(response.Response.GroupInfo))
		if count == *response.Response.TotalNum {
			break
		}
		*request.Page = *request.Page + 1

	}

	return groupInfos
}

func listAccessKeys(ctx context.Context, cli *cam.Client, uin *uint64) []*cam.AccessKey {
	request := cam.NewListAccessKeysRequest()
	request.TargetUin = uin

	response, err := cli.ListAccessKeys(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListAccessKeys error", zap.Error(err))
		return nil
	}
	return response.Response.AccessKeys
}
