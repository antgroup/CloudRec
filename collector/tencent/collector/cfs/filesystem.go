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

package cfs

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/tencent/collector"
	cfs "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cfs/v20190719"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"go.uber.org/zap"
)

func GetFileSystemResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CFS,
		ResourceTypeName:   "CFS FileSystem",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://cloud.tencent.com/document/api/582/38170",
		ResourceDetailFunc: ListFileSystemResource,
		RowField: schema.RowField{
			ResourceId:   "$.FileSystemInfo.FileSystemId",
			ResourceName: "$.FileSystemInfo.FsName",
		},
		Dimension: schema.Regional,
	}
}

type FileSystemDetail struct {
	FileSystemInfo cfs.FileSystemInfo
	RuleList       []*cfs.PGroupRuleInfo
	MountTargets   []*cfs.MountInfo
}

func ListFileSystemResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CFS

	request := cfs.NewDescribeCfsFileSystemsRequest()

	response, err := cli.DescribeCfsFileSystems(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeCfsFileSystems error", zap.Error(err))
		return err
	}

	for _, fileSystem := range response.Response.FileSystems {
		d := &FileSystemDetail{
			FileSystemInfo: *fileSystem,
			RuleList:       describeCfsRules(ctx, cli, *fileSystem.PGroup.PGroupId),
			MountTargets:   describeMountTargets(ctx, cli, *fileSystem.FileSystemId),
		}
		res <- d
	}

	return nil
}

func describeCfsRules(ctx context.Context, cli *cfs.Client, PGroupId string) (ruleList []*cfs.PGroupRuleInfo) {
	request := cfs.NewDescribeCfsRulesRequest()
	request.PGroupId = common.StringPtr(PGroupId)

	response, err := cli.DescribeCfsRules(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeCfsRules error", zap.Error(err))
		return
	}

	return response.Response.RuleList
}

func describeMountTargets(ctx context.Context, cli *cfs.Client, FileSystemId string) (MountTargets []*cfs.MountInfo) {
	request := cfs.NewDescribeMountTargetsRequest()
	request.FileSystemId = common.StringPtr(FileSystemId)

	response, err := cli.DescribeMountTargets(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeMountTargets error", zap.Error(err))
		return
	}

	return response.Response.MountTargets
}
