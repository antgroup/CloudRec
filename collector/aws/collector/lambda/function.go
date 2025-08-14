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

package lambda

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"sync"
)

const (
	maxWorkers = 10
)

// GetFunctionResource returns a Function Resource
func GetFunctionResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Lambda,
		ResourceTypeName:   "Lambda Function",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               `https://docs.aws.amazon.com/lambda/latest/dg/API_ListFunctions.html`,
		ResourceDetailFunc: GetFunctionDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Function.FunctionArn",
			ResourceName: "$.Function.FunctionName",
		},
		Dimension: schema.Regional,
	}
}

// FunctionDetail aggregates all information for a single Lambda function.
type FunctionDetail struct {
	Function   types.FunctionConfiguration
	Policy     map[string]interface{}
	URLConfigs []types.FunctionUrlConfig
	Tags       map[string]string
}

// GetFunctionDetail fetches the details for all Lambda functions in a region.
func GetFunctionDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Lambda

	functions, err := listFunctions(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list lambda functions", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.FunctionConfiguration, len(functions))

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for function := range tasks {
				detail := describeFunctionDetail(ctx, client, function)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks to the queue
	for _, function := range functions {
		tasks <- function
	}
	close(tasks)

	wg.Wait()

	return nil
}

// describeFunctionDetail fetches all details for a single function.
func describeFunctionDetail(ctx context.Context, client *lambda.Client, function types.FunctionConfiguration) *FunctionDetail {
	var wg sync.WaitGroup
	var policy map[string]interface{}
	var urlConfigs []types.FunctionUrlConfig
	var tags map[string]string

	wg.Add(3)

	go func() {
		defer wg.Done()
		policy, _ = getPolicy(ctx, client, function.FunctionName)
	}()

	go func() {
		defer wg.Done()
		urlConfigs, _ = listFunctionURLConfigs(ctx, client, function.FunctionName)
	}()

	go func() {
		defer wg.Done()
		tags, _ = listTags(ctx, client, function.FunctionArn)
	}()

	wg.Wait()

	return &FunctionDetail{
		Function:   function,
		Policy:     policy,
		URLConfigs: urlConfigs,
		Tags:       tags,
	}
}

// listFunctions retrieves all Lambda functions in a region.
func listFunctions(ctx context.Context, c *lambda.Client) ([]types.FunctionConfiguration, error) {
	var functions []types.FunctionConfiguration
	paginator := lambda.NewListFunctionsPaginator(c, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		functions = append(functions, page.Functions...)
	}
	return functions, nil
}

// getPolicy retrieves the resource-based policy for a function.
func getPolicy(ctx context.Context, c *lambda.Client, functionName *string) (map[string]interface{}, error) {
	output, err := c.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: functionName})
	if err != nil {
		// It's common for a function not to have a policy, so we just log it as debug.
		log.CtxLogger(ctx).Debug("failed to get lambda policy", zap.String("functionName", *functionName), zap.Error(err))
		return nil, err
	}

	var policy map[string]interface{}
	err = json.Unmarshal([]byte(*output.Policy), &policy)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to unmarshal lambda policy", zap.String("functionName", *functionName), zap.Error(err))
		return nil, err
	}
	return policy, nil
}

// listFunctionURLConfigs retrieves the URL configs for a function.
func listFunctionURLConfigs(ctx context.Context, c *lambda.Client, functionName *string) ([]types.FunctionUrlConfig, error) {
	var urlConfigs []types.FunctionUrlConfig
	paginator := lambda.NewListFunctionUrlConfigsPaginator(c, &lambda.ListFunctionUrlConfigsInput{FunctionName: functionName})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Debug("failed to list function url configs", zap.String("functionName", *functionName), zap.Error(err))
			return nil, err
		}
		urlConfigs = append(urlConfigs, output.FunctionUrlConfigs...)
	}
	return urlConfigs, nil
}

// listTags retrieves all tags for a function.
func listTags(ctx context.Context, c *lambda.Client, functionArn *string) (map[string]string, error) {
	output, err := c.ListTags(ctx, &lambda.ListTagsInput{Resource: functionArn})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list lambda tags", zap.String("functionArn", *functionArn), zap.Error(err))
		return nil, err
	}
	return output.Tags, nil
}
