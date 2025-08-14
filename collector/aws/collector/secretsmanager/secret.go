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

package secretsmanager

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"sync"
)

const maxWorkers = 10

// GetSecretResource returns a Secret Resource
func GetSecretResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Secret,
		ResourceTypeName:   "Secret",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html",
		ResourceDetailFunc: GetSecretDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Secret.ARN",
			ResourceName: "$.Secret.Name",
		},
		Dimension: schema.Regional,
	}
}

// SecretDetail aggregates all information for a single Secrets Manager secret.
type SecretDetail struct {
	Secret types.SecretListEntry
	Policy *map[string]interface{}
}

// GetSecretDetail fetches the details for all Secrets Manager secrets.
func GetSecretDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).SecretsManager

	secrets, err := listSecrets(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list secrets", zap.Error(err))
		return err
	}

	jobs := make(chan types.SecretListEntry, len(secrets))
	var wg sync.WaitGroup
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for secret := range jobs {
				detail := describeSecretDetail(ctx, client, secret)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}
	for _, secret := range secrets {
		jobs <- secret
	}
	close(jobs)
	wg.Wait()

	return nil
}

// describeSecretDetail fetches all details for a single secret.
func describeSecretDetail(ctx context.Context, client *secretsmanager.Client, secret types.SecretListEntry) *SecretDetail {
	var wg sync.WaitGroup
	var policy *map[string]interface{}

	wg.Add(1)

	go func() {
		defer wg.Done()
		policyResult, err := getResourcePolicy(ctx, client, secret.ARN)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to get resource policy", zap.String("secret", *secret.ARN), zap.Error(err))
		} else {
			policy = policyResult
		}
	}()

	wg.Wait()

	return &SecretDetail{
		Secret: secret,
		Policy: policy,
	}
}

// listSecrets retrieves all Secrets Manager secrets.
func listSecrets(ctx context.Context, c *secretsmanager.Client) ([]types.SecretListEntry, error) {
	var secrets []types.SecretListEntry
	paginator := secretsmanager.NewListSecretsPaginator(c, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, page.SecretList...)
	}
	return secrets, nil
}

// getResourcePolicy retrieves the resource policy for a secret.
func getResourcePolicy(ctx context.Context, c *secretsmanager.Client, secretArn *string) (*map[string]interface{}, error) {
	output, err := c.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
		SecretId: secretArn,
	})
	if err != nil {
		return nil, err
	}
	
	if output.ResourcePolicy == nil {
		return nil, nil
	}
	
	var policy map[string]interface{}
	err = json.Unmarshal([]byte(*output.ResourcePolicy), &policy)
	if err != nil {
		return nil, err
	}
	
	return &policy, nil
}

