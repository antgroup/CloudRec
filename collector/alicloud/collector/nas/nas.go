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

package nas

import (
	"context"
	nas "github.com/alibabacloud-go/nas-20170626/v3/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetNASResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NAS,
		ResourceTypeName:   collector.NAS,
		ResourceGroupType:  constant.STORE,
		Desc:               "https://api.aliyun.com/product/NAS",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.FileSystem.FileSystemId",
			ResourceName: "$.FileSystem.FileSystemId",
		},
		Regions: []string{
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
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).NAS
	describeFileSystemsRequest := &nas.DescribeFileSystemsRequest{}
	describeFileSystemsRequest.PageSize = tea.Int32(100)
	describeFileSystemsRequest.PageNumber = tea.Int32(1)
	count := 0

	for {
		runtime := &util.RuntimeOptions{}
		fileSystemInfo, err := cli.DescribeFileSystemsWithOptions(describeFileSystemsRequest, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeFileSystems error", zap.Error(err))
			return err
		}

		// If the region has no scaling group, skip subsequent queries
		if len(fileSystemInfo.Body.FileSystems.FileSystem) == 0 {
			return nil
		}

		for _, filesystem := range fileSystemInfo.Body.FileSystems.FileSystem {
			res <- Detail{
				RegionId:     cli.RegionId,
				FileSystem:   filesystem,
				ResourceName: *filesystem.FileSystemType + *filesystem.FileSystemId,
				AccessPoint:  describeAccessPoint(ctx, cli, filesystem.FileSystemId),
				AccessGroup:  describeAccessGroup(ctx, cli),
				SmbAcl:       describeSmbAcl(ctx, cli, filesystem.FileSystemId),
				NfsAcl:       describeNfsAcl(ctx, cli, filesystem.FileSystemId),
			}
			count++
		}

		if count >= int(*fileSystemInfo.Body.TotalCount) {
			break
		}
		describeFileSystemsRequest.PageNumber = tea.Int32(*describeFileSystemsRequest.PageNumber + 1)
	}
	return nil
}

type Detail struct {
	// region
	RegionId *string

	ResourceName string

	// File system information
	FileSystem *nas.DescribeFileSystemsResponseBodyFileSystemsFileSystem

	// Mount point information
	AccessPoint []*nas.DescribeAccessPointsResponseBodyAccessPoints

	// Permission group information
	AccessGroup *nas.DescribeAccessGroupsResponseBodyAccessGroups

	// SMB AD ACL info
	SmbAcl *nas.DescribeSmbAclResponseBodyAcl

	// NFS nas ACL info
	NfsAcl *nas.DescribeNfsAclResponseBodyAcl
}

// Query access point information
func describeAccessPoint(ctx context.Context, cli *nas.Client, fileSystemId *string) []*nas.DescribeAccessPointsResponseBodyAccessPoints {
	describeAccessPointsRequest := &nas.DescribeAccessPointsRequest{}
	describeAccessPointsRequest.FileSystemId = fileSystemId
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeAccessPointsWithOptions(describeAccessPointsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAccessPointsWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.AccessPoints
}

// Query permission groups
func describeAccessGroup(ctx context.Context, cli *nas.Client) *nas.DescribeAccessGroupsResponseBodyAccessGroups {
	describeAccessGroupsRequest := &nas.DescribeAccessGroupsRequest{}
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeAccessGroupsWithOptions(describeAccessGroupsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAccessGroupsWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.AccessGroups

}

// Query the SMB AD ACL
func describeSmbAcl(ctx context.Context, cli *nas.Client, fileSystemId *string) *nas.DescribeSmbAclResponseBodyAcl {
	describeSmbAclRequest := &nas.DescribeSmbAclRequest{}
	describeSmbAclRequest.FileSystemId = fileSystemId
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeSmbAclWithOptions(describeSmbAclRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeSmbAclWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Acl
}

// Query the NFS NAS ACL
func describeNfsAcl(ctx context.Context, cli *nas.Client, fileSystemId *string) *nas.DescribeNfsAclResponseBodyAcl {
	describeNfsAclRequest := &nas.DescribeNfsAclRequest{}
	describeNfsAclRequest.FileSystemId = fileSystemId
	runtime := &util.RuntimeOptions{}

	result, err := cli.DescribeNfsAclWithOptions(describeNfsAclRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeNfsAclWithOptions error", zap.Error(err))
		return nil
	}
	return result.Body.Acl
}
