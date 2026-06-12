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

package ecr

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetRepositoryResource returns a Repository Resource
func GetRepositoryResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Repository,
		ResourceTypeName:   collector.Repository,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               ``,
		ResourceDetailFunc: GetRepositoryDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Repository.RepositoryName",
			ResourceName: "$.Repository.RepositoryName",
		},
		Regions:   []string{"ap-northeast-1", "cn-north-1"},
		Dimension: schema.Regional,
	}
}

type RepositoryDetail struct {
	Repository types.Repository

	// The policy for the repository
	RepositoryPolicy *string
}

// GetRepositoryDetail streams each ECR repository detail as the
// DescribeRepositories pagination yields it and its policy fetch
// completes, avoiding the 30s consumer idle timeout in core-sdk
// schema/platform.go when a region has many repositories.
func GetRepositoryDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECR

	input := &ecr.DescribeRepositoriesInput{}
	for {
		output, err := client.DescribeRepositories(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeRepositories error", zap.Error(err))
			return err
		}
		for _, repository := range output.Repositories {
			res <- RepositoryDetail{
				Repository:       repository,
				RepositoryPolicy: getRepositoryPolicy(ctx, client, repository),
			}
		}
		if output.NextToken == nil {
			return nil
		}
		input.NextToken = output.NextToken
	}
}

func getRepositoryPolicy(ctx context.Context, c *ecr.Client, repository types.Repository) *string {
	input := &ecr.GetRepositoryPolicyInput{
		RepositoryName: repository.RepositoryName,
		// The default registry will be assumed.
		RegistryId: nil,
	}
	output, err := c.GetRepositoryPolicy(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetRepositoryPolicy error", zap.Error(err))
		return nil
	}
	if output.PolicyText != nil {
		return output.PolicyText
	}

	return nil
}
