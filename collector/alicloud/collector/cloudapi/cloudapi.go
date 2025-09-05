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

package cloudapi

import (
	"context"
	"go.uber.org/zap"

	cloudapi20160714 "github.com/alibabacloud-go/cloudapi-20160714/v5/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
)

func GetCloudAPIResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudAPI,
		ResourceTypeName:   collector.CloudAPI,
		ResourceGroupType:  constant.CONFIG,
		Desc:               "https://api.aliyun.com/product/CloudAPI",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
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
			"cn-heyuan",
			"cn-guangzhou",
			"ap-southeast-6",
			"ap-northeast-2",
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
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.CloudAPI

	describeInstancesRequest := &cloudapi20160714.DescribeInstancesRequest{}
	runtime := &util.RuntimeOptions{}

	describeInstancesResponse, err := cli.DescribeInstancesWithOptions(describeInstancesRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstancesWithOptions error", zap.Error(err))
		return err
	}
	for _, i := range describeInstancesResponse.Body.Instances.InstanceAttribute {
		res <- Detail{
			Instance: i,
			Acl:      describeACL(ctx, cli, i.AclName),
			LogInfo:  describeLogConfig(ctx, cli),
		}
	}

	return nil

}

type Detail struct {

	// Instance attribute
	Instance *cloudapi20160714.DescribeInstancesResponseBodyInstancesInstanceAttribute

	// ACL Information
	Acl []*cloudapi20160714.DescribeAccessControlListsResponseBodyAclsAcl

	// Log information
	LogInfo []*cloudapi20160714.DescribeLogConfigResponseBodyLogInfosLogInfo
}

// Query ACL information
func describeACL(ctx context.Context, cli *cloudapi20160714.Client, aclName *string) []*cloudapi20160714.DescribeAccessControlListsResponseBodyAclsAcl {
	describeAccessControlListsRequest := &cloudapi20160714.DescribeAccessControlListsRequest{AclName: aclName}
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeAccessControlListsWithOptions(describeAccessControlListsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAccessControlListsWithOptions error", zap.Error(err))
		return nil
	}

	if *result.Body.TotalCount == 0 {
		return nil
	}
	return result.Body.Acls.Acl
}

// Query log information
func describeLogConfig(ctx context.Context, cli *cloudapi20160714.Client) []*cloudapi20160714.DescribeLogConfigResponseBodyLogInfosLogInfo {
	describeLogConfigRequest := &cloudapi20160714.DescribeLogConfigRequest{}
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeLogConfigWithOptions(describeLogConfigRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeLogConfigWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.LogInfos.LogInfo
}
