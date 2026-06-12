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
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
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

// GetFileSystemDetail streams each EFS file system detail as the
// DescribeFileSystems pagination yields it and its policy fetch completes,
// avoiding the 30s consumer idle timeout in core-sdk schema/platform.go
// when a region has many file systems.
func GetFileSystemDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EFS

	input := &efs.DescribeFileSystemsInput{}
	for {
		output, err := client.DescribeFileSystems(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeFileSystems error", zap.Error(err))
			return err
		}
		for _, fileSystem := range output.FileSystems {
			res <- FileSystemDetail{
				FileSystem:       fileSystem,
				FileSystemPolicy: getFileSystemPolicy(ctx, client, fileSystem),
			}
		}
		if output.NextMarker == nil {
			return nil
		}
		input.Marker = output.NextMarker
	}
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
