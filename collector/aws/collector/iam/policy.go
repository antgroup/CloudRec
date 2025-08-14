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

package iam

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"sync"
)

// GetPolicyResource returns a Policy Resource
func GetPolicyResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.IAMPolicy,
		ResourceTypeName:   "IAM Policy",
		ResourceGroupType:  constant.IDENTITY,
		Desc:               `https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html`,
		ResourceDetailFunc: GetPolicyDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Policy.Arn",
			ResourceName: "$.Policy.PolicyName",
		},
		Dimension: schema.Global,
	}
}

// PolicyDetail aggregates all information for a single IAM policy.
type PolicyDetail struct {
	Policy  types.Policy
	Version *types.PolicyVersion
	Tags    []types.Tag
}

// GetPolicyDetail fetches the details for all customer managed IAM policies.
func GetPolicyDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).IAM

	policies, err := listPolicies(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list policies", zap.Error(err))
		return err
	}

	const numWorkers = 10 // A reasonable number of concurrent workers. Consider making this configurable.
	jobs := make(chan types.Policy, len(policies))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				res <- describePolicyDetail(ctx, client, p)
			}
		}()
	}

	for _, policy := range policies {
		jobs <- policy
	}
	close(jobs)

	wg.Wait()

	return nil
}

// describePolicyDetail fetches all details for a single policy.
func describePolicyDetail(ctx context.Context, client *iam.Client, policy types.Policy) PolicyDetail {
	var wg sync.WaitGroup
	var version *types.PolicyVersion
	var tags []types.Tag

	wg.Add(2)

	go func() {
		defer wg.Done()
		version, _ = getPolicyVersion(ctx, client, policy.Arn, policy.DefaultVersionId)
	}()

	go func() {
		defer wg.Done()
		tags, _ = listPolicyTags(ctx, client, policy.Arn)
	}()

	wg.Wait()

	return PolicyDetail{
		Policy:  policy,
		Version: version,
		Tags:    tags,
	}
}

// listPolicies retrieves all customer managed IAM policies.
func listPolicies(ctx context.Context, c *iam.Client) ([]types.Policy, error) {
	var policies []types.Policy
	paginator := iam.NewListPoliciesPaginator(c, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		policies = append(policies, page.Policies...)
	}
	return policies, nil
}

// getPolicyVersion retrieves the specified version of a policy.
func getPolicyVersion(ctx context.Context, c *iam.Client, policyArn *string, versionId *string) (*types.PolicyVersion, error) {
	output, err := c.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policyArn, VersionId: versionId})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get policy version", zap.String("policyArn", *policyArn), zap.Error(err))
		return nil, err
	}
	return output.PolicyVersion, nil
}

// listPolicyTags retrieves all tags for a policy.
func listPolicyTags(ctx context.Context, c *iam.Client, policyArn *string) ([]types.Tag, error) {
	var tags []types.Tag
	paginator := iam.NewListPolicyTagsPaginator(c, &iam.ListPolicyTagsInput{PolicyArn: policyArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list policy tags", zap.String("policyArn", *policyArn), zap.Error(err))
			return nil, err
		}
		tags = append(tags, page.Tags...)
	}
	return tags, nil
}
