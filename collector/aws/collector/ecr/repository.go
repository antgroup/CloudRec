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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cloudrec/aws/collector"
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
		Dimension: schema.Global,
	}
}

type RepositoryDetail struct {
	Repository types.Repository

	// The policy for the repository
	RepositoryPolicy *string
}

func GetRepositoryDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECR
	repositoryDetails, err := describeRepositoryDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeRepositoryDetails error", zap.Error(err))
		return err
	}
	for _, repositoryDetail := range repositoryDetails {

		res <- repositoryDetail
	}

	return nil
}

func describeRepositoryDetails(ctx context.Context, c *ecr.Client) (repositoryDetails []RepositoryDetail, err error) {
	repositories, err := describeRepositories(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeRepositories error", zap.Error(err))
		return nil, err
	}
	for _, repository := range repositories {
		repositoryDetails = append(repositoryDetails, RepositoryDetail{
			Repository:       repository,
			RepositoryPolicy: getRepositoryPolicy(ctx, c, repository),
		})
	}

	return repositoryDetails, nil
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

func describeRepositories(ctx context.Context, svc *ecr.Client) (repositories []types.Repository, err error) {
	input := &ecr.DescribeRepositoriesInput{}
	output, err := svc.DescribeRepositories(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeRepositories error", zap.Error(err))
		return nil, err
	}
	repositories = append(repositories, output.Repositories...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = svc.DescribeRepositories(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeRepositories error", zap.Error(err))
			return nil, err
		}
		repositories = append(repositories, output.Repositories...)
	}

	return repositories, nil
}
