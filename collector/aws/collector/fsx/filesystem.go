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

package fsx

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/cloudrec/aws/collector"
	"go.uber.org/zap"
)

// GetFsxFileSystemResource returns a FSx file system Resource
func GetFsxFileSystemResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.FSxFileSystem,
		ResourceTypeName:   collector.FSxFileSystem,
		ResourceGroupType:  constant.STORE,
		Desc:               `https://docs.aws.amazon.com/fsx/latest/APIReference/API_DescribeFileSystems.html`,
		ResourceDetailFunc: GetFileSystemDetail,
		RowField: schema.RowField{
			ResourceId:   "$.FileSystem.FileSystemId",
			ResourceName: "$.FileSystem.DNSName",
			Address:      "$.FileSystem.DNSName",
		},
		Dimension: schema.Regional,
	}
}

type FileSystemDetail struct {

	// A description of the file system.
	FileSystem types.FileSystem

	// An array of one or more DNS aliases currently associated with the specified
	// file system.
	Aliases []types.Alias
}

func GetFileSystemDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).FSx

	fileSystemDetails, err := describeFileSystemDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeFileSystemDetails error", zap.Error(err))
		return err
	}

	for _, fileSystemDetail := range fileSystemDetails {
		res <- fileSystemDetail
	}
	return nil
}

func describeFileSystemDetails(ctx context.Context, c *fsx.Client) (fileSystemDetails []FileSystemDetail, err error) {

	fileSystems, err := describeFileSystem(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeFileSystem error", zap.Error(err))
		return nil, err
	}
	for _, fileSystem := range fileSystems {
		fileSystemDetails = append(fileSystemDetails, FileSystemDetail{
			FileSystem: fileSystem,
			Aliases:    describeFileSystemAliases(ctx, c, fileSystem),
		})
	}
	return fileSystemDetails, nil
}

func describeFileSystemAliases(ctx context.Context, c *fsx.Client, system types.FileSystem) (aliases []types.Alias) {
	input := &fsx.DescribeFileSystemAliasesInput{}
	output, err := c.DescribeFileSystemAliases(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeFileSystemAliases error", zap.Error(err))
		return nil
	}
	aliases = append(aliases, output.Aliases...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeFileSystemAliases(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("describeFileSystemAliases error", zap.Error(err))
			return nil
		}
		aliases = append(aliases, output.Aliases...)
	}

	return aliases
}

func describeFileSystem(ctx context.Context, c *fsx.Client) (fileSystems []types.FileSystem, err error) {
	input := &fsx.DescribeFileSystemsInput{}
	output, err := c.DescribeFileSystems(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeFileSystems error", zap.Error(err))
		return nil, err
	}
	fileSystems = append(fileSystems, output.FileSystems...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = c.DescribeFileSystems(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("describeFileSystems error", zap.Error(err))
			return nil, err
		}
		fileSystems = append(fileSystems, output.FileSystems...)
	}

	return fileSystems, nil
}
