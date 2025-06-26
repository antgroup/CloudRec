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

package efs

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/cloudrec/aws/collector"
	"go.uber.org/zap"
)

// GetEFSFileSystemResource returns a EFS file system Resource
func GetEFSFileSystemResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EFSFileSystem,
		ResourceTypeName:   collector.EFSFileSystem,
		ResourceGroupType:  constant.STORE,
		Desc:               `https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html`,
		ResourceDetailFunc: GetFileSystemDetail,
		RowField: schema.RowField{
			ResourceId:   "$.FileSystem.FileSystemId",
			ResourceName: "$.FileSystem.Name",
		},
		Dimension: schema.Regional,
	}
}

type FileSystemDetail struct {

	// A description of the file system.
	FileSystem types.FileSystemDescription

	// FileSystemPolicy for the EFS file system.
	FileSystemPolicy map[string]interface{}
}

func GetFileSystemDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EFS

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

func describeFileSystemDetails(ctx context.Context, c *efs.Client) (fileSystemDetails []FileSystemDetail, err error) {
	fileSystems, err := describeFileSystem(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeFileSystem error", zap.Error(err))
		return nil, err
	}
	for _, fileSystem := range fileSystems {
		fileSystemDetails = append(fileSystemDetails, FileSystemDetail{
			FileSystem:       fileSystem,
			FileSystemPolicy: getFileSystemPolicy(ctx, c, fileSystem),
		})
	}
	return fileSystemDetails, nil
}

func getFileSystemPolicy(ctx context.Context, c *efs.Client, fileSystem types.FileSystemDescription) (policy map[string]interface{}) {
	input := &efs.DescribeFileSystemPolicyInput{
		FileSystemId: fileSystem.FileSystemId,
	}
	output, err := c.DescribeFileSystemPolicy(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeFileSystemPolicy error", zap.Error(err))
		return nil
	}

	err = json.Unmarshal([]byte(*output.Policy), &policy)
	if err != nil {
		log.CtxLogger(ctx).Warn("Unmarshal error", zap.Error(err))
		return nil
	}
	return policy
}

func describeFileSystem(ctx context.Context, c *efs.Client) (fileSystems []types.FileSystemDescription, err error) {
	input := &efs.DescribeFileSystemsInput{}
	output, err := c.DescribeFileSystems(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeFileSystems error", zap.Error(err))
		return nil, err
	}
	fileSystems = append(fileSystems, output.FileSystems...)
	for output.NextMarker != nil {
		input.Marker = output.NextMarker
		output, err = c.DescribeFileSystems(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeFileSystems error", zap.Error(err))
			return nil, err
		}
		fileSystems = append(fileSystems, output.FileSystems...)
	}
	return fileSystems, nil
}
