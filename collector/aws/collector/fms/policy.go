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

package fms

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fms"
	"github.com/aws/aws-sdk-go-v2/service/fms/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetPolicyResource returns AWS Firewall Manager policy resource definition
func GetPolicyResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.FMS,
		ResourceTypeName:   "Firewall Manager Policy",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/fms/2018-01-01/APIReference/API_ListPolicies.html",
		ResourceDetailFunc: GetPolicyDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Policy.PolicyId",
			ResourceName: "$.Policy.PolicyName",
		},
		Dimension: schema.Global,
	}
}

// PolicyDetail aggregates all information for a single Firewall Manager policy.
type PolicyDetail struct {
	Policy           types.Policy
	ComplianceStatus []types.PolicyComplianceStatus
	Tags             map[string]string
}

// GetPolicyDetail fetches the details for all Firewall Manager policies.
func GetPolicyDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).FMS

	policies, err := listPolicies(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Firewall Manager policies", zap.Error(err))
		return err
	}

	for _, policy := range policies {

		policyDetail, err := getPolicy(ctx, client, policy.PolicyId)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to get policy", zap.String("policyId", *policy.PolicyId), zap.Error(err))
			continue
		}

		complianceStatus, err := listComplianceStatus(ctx, client, policy.PolicyId)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list compliance status", zap.String("policyId", *policy.PolicyId), zap.Error(err))
			continue
		}

		tags, err := listPolicyTags(ctx, client, policy.PolicyId)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list policy tags", zap.String("policyId", *policy.PolicyId), zap.Error(err))
			continue
		}

		res <- &PolicyDetail{
			Policy:           *policyDetail,
			ComplianceStatus: complianceStatus,
			Tags:             tags,
		}
	}
	return nil
}

// listPolicies retrieves all Firewall Manager policies.
func listPolicies(ctx context.Context, c *fms.Client) ([]types.PolicySummary, error) {
	var policies []types.PolicySummary
	input := &fms.ListPoliciesInput{
		MaxResults: aws.Int32(100),
	}

	paginator := fms.NewListPoliciesPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		policies = append(policies, page.PolicyList...)
	}
	return policies, nil
}

// getPolicy retrieves details for a single policy.
func getPolicy(ctx context.Context, c *fms.Client, policyId *string) (*types.Policy, error) {
	input := &fms.GetPolicyInput{
		PolicyId: policyId,
	}
	output, err := c.GetPolicy(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get policy", zap.String("policyId", *policyId), zap.Error(err))
		return nil, err
	}
	return output.Policy, nil
}

// listComplianceStatus retrieves compliance status for a single policy.
func listComplianceStatus(ctx context.Context, c *fms.Client, policyId *string) ([]types.PolicyComplianceStatus, error) {
	var complianceStatus []types.PolicyComplianceStatus
	input := &fms.ListComplianceStatusInput{
		PolicyId:   policyId,
		MaxResults: aws.Int32(100),
	}

	paginator := fms.NewListComplianceStatusPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list compliance status", zap.String("policyId", *policyId), zap.Error(err))
			return nil, err
		}
		complianceStatus = append(complianceStatus, page.PolicyComplianceStatusList...)
	}
	return complianceStatus, nil
}

// listPolicyTags retrieves tags for a single policy.
func listPolicyTags(ctx context.Context, c *fms.Client, policyId *string) (map[string]string, error) {
	input := &fms.ListTagsForResourceInput{
		ResourceArn: policyId,
	}
	output, err := c.ListTagsForResource(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for policy", zap.String("policyId", *policyId), zap.Error(err))
		return make(map[string]string), err
	}

	tags := make(map[string]string)
	for _, tag := range output.TagList {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags, nil
}
