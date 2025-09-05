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

// GetRegistryResource returns a Registry Resource
func GetRegistryResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Registry,
		ResourceTypeName:   collector.Registry,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               ``,
		ResourceDetailFunc: GetRegistryDetail,
		RowField: schema.RowField{
			ResourceId:   "$.RegistryId",
			ResourceName: "$.RegistryId",
			Address:      "",
		},
		Dimension: schema.Global,
	}
}

type RegistryDetail struct {

	// The RegistryId
	RegistryId *string

	ReplicationConfiguration *types.ReplicationConfiguration

	// The permissions policy for registry
	RegistryPolicy *string
}

func GetRegistryDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ECR

	registryDetail, err := describeRegistryDetail(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeRegistryDetail error", zap.Error(err))
		return err
	}

	res <- registryDetail

	return nil
}

func describeRegistryDetail(ctx context.Context, c *ecr.Client) (registryDetail RegistryDetail, err error) {

	output, err := c.DescribeRegistry(ctx, &ecr.DescribeRegistryInput{})
	if err != nil {
		return registryDetail, err
	}
	registryDetail = RegistryDetail{
		RegistryId:               output.RegistryId,
		ReplicationConfiguration: output.ReplicationConfiguration,
		RegistryPolicy:           getRegistryPolicy(ctx, c),
	}

	return registryDetail, nil
}

func getRegistryPolicy(ctx context.Context, c *ecr.Client) *string {
	output, err := c.GetRegistryPolicy(ctx, &ecr.GetRegistryPolicyInput{})
	if err != nil {
		log.CtxLogger(ctx).Warn("GetRegistryPolicy error", zap.Error(err))
		return nil
	}
	if output.PolicyText != nil {
		return output.PolicyText
	}
	return nil
}
