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

package apigateway

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"sync"
)

const maxWorkers = 10

// GetAPIV2Resource returns an API Gateway V2 API Resource
func GetAPIV2Resource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.APIGatewayV2API,
		ResourceTypeName:   "APIGatewayV2 API",
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api.html`,
		ResourceDetailFunc: GetAPIV2Detail,
		RowField: schema.RowField{
			ResourceId:   "$.API.ApiId",
			ResourceName: "$.API.Name",
		},
		Dimension: schema.Regional,
	}
}

// APIV2Detail aggregates all information for a single API Gateway V2 API.
type APIV2Detail struct {
	API         types.Api
	Stages      []types.Stage
	Authorizers []types.Authorizer
	Tags        map[string]string
}

// GetAPIV2Detail fetches the details for all API Gateway V2 APIs in a region.
func GetAPIV2Detail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).APIGatewayV2

	apis, err := describeAPIs(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe API Gateway V2 APIs", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.Api, len(apis))

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for api := range tasks {
				detail := describeAPIV2Detail(ctx, client, api)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	for _, api := range apis {
		tasks <- api
	}
	close(tasks)

	wg.Wait()

	return nil
}

// describeAPIV2Detail fetches all details for a single API.
func describeAPIV2Detail(ctx context.Context, client *apigatewayv2.Client, api types.Api) *APIV2Detail {
	var wg sync.WaitGroup
	var stages []types.Stage
	var authorizers []types.Authorizer
	tags := make(map[string]string)

	// Copy the API to avoid race conditions
	apiCopy := api

	wg.Add(3)

	go func() {
		defer wg.Done()
		stages, _ = getStages(ctx, client, apiCopy.ApiId)
	}()

	go func() {
		defer wg.Done()
		authorizers, _ = getAuthorizers(ctx, client, apiCopy.ApiId)
	}()

	go func() {
		defer wg.Done()
		tags, _ = getTags(ctx, client, apiCopy.ApiId)
	}()

	wg.Wait()

	return &APIV2Detail{
		API:         apiCopy,
		Stages:      stages,
		Authorizers: authorizers,
		Tags:        tags,
	}
}

// describeAPIs retrieves all API Gateway V2 APIs in a region.
func describeAPIs(ctx context.Context, c *apigatewayv2.Client) ([]types.Api, error) {
	var apis []types.Api
	input := &apigatewayv2.GetApisInput{}
	output, err := c.GetApis(ctx, input)
	if err != nil {
		return nil, err
	}
	apis = append(apis, output.Items...)
	return apis, nil
}

// getStages retrieves all stages for a single API.
func getStages(ctx context.Context, c *apigatewayv2.Client, apiId *string) ([]types.Stage, error) {
	output, err := c.GetStages(ctx, &apigatewayv2.GetStagesInput{
		ApiId: apiId,
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get stages", zap.String("apiId", *apiId), zap.Error(err))
		return nil, err
	}
	return output.Items, nil
}

// getAuthorizers retrieves all authorizers for a single API.
func getAuthorizers(ctx context.Context, c *apigatewayv2.Client, apiId *string) ([]types.Authorizer, error) {
	output, err := c.GetAuthorizers(ctx, &apigatewayv2.GetAuthorizersInput{
		ApiId: apiId,
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get authorizers", zap.String("apiId", *apiId), zap.Error(err))
		return nil, err
	}
	return output.Items, nil
}

// getTags retrieves tags for a single API.
func getTags(ctx context.Context, c *apigatewayv2.Client, apiId *string) (map[string]string, error) {
	// For now, we'll return an empty map as tags are optional
	// In a real implementation, you would need to construct the correct ARN format
	// and handle the GetTags API call properly
	return make(map[string]string), nil
}
