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

package kms

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
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

// GetKeyResource returns a Key Resource
func GetKeyResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.KMS,
		ResourceTypeName:   "KMS Key",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html`,
		ResourceDetailFunc: GetKeyDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Key.KeyId",
			ResourceName: "$.Key.KeyId", // No friendly name available, use ID
		},
		Dimension: schema.Regional,
	}
}

// KeyDetail aggregates all information for a single KMS key.
type KeyDetail struct {
	Key             *types.KeyMetadata
	RotationEnabled *bool
	Policy          map[string]interface{}
	Tags            []types.Tag
}

// GetKeyDetail fetches the details for all KMS keys in a region.
func GetKeyDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).KMS

	keys, err := listKeys(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list kms keys", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.KeyListEntry, len(keys))

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range tasks {
				detail := describeKeyDetail(ctx, client, key.KeyId)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks to the queue
	for _, key := range keys {
		tasks <- key
	}
	close(tasks)

	wg.Wait()

	return nil
}

// describeKeyDetail fetches all details for a single key.
func describeKeyDetail(ctx context.Context, client *kms.Client, keyId *string) *KeyDetail {
	keyMetadata, err := describeKey(ctx, client, keyId)
	if err != nil {
		// If we can't describe the key, we can't get any more info, so skip it.
		return nil
	}

	// Only customer-managed keys have rotation status, policies, and tags that can be managed.
	if keyMetadata.KeyManager != types.KeyManagerTypeCustomer {
		return &KeyDetail{Key: keyMetadata}
	}

	var wg sync.WaitGroup
	var rotationEnabled *bool
	var policy map[string]interface{}
	var tags []types.Tag

	wg.Add(3)

	go func() {
		defer wg.Done()
		rotationEnabled, _ = getKeyRotationStatus(ctx, client, keyId)
	}()

	go func() {
		defer wg.Done()
		policy, _ = getKeyPolicy(ctx, client, keyId)
	}()

	go func() {
		defer wg.Done()
		tags, _ = listResourceTags(ctx, client, keyId)
	}()

	wg.Wait()

	return &KeyDetail{
		Key:             keyMetadata,
		RotationEnabled: rotationEnabled,
		Policy:          policy,
		Tags:            tags,
	}
}

// listKeys retrieves all KMS keys in a region.
func listKeys(ctx context.Context, c *kms.Client) ([]types.KeyListEntry, error) {
	var keys []types.KeyListEntry
	paginator := kms.NewListKeysPaginator(c, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		keys = append(keys, page.Keys...)
	}
	return keys, nil
}

// describeKey retrieves the metadata for a single KMS key.
func describeKey(ctx context.Context, c *kms.Client, keyId *string) (*types.KeyMetadata, error) {
	output, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: keyId})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to describe key", zap.String("keyId", *keyId), zap.Error(err))
		return nil, err
	}
	return output.KeyMetadata, nil
}

// getKeyRotationStatus checks if automatic rotation is enabled for a key.
func getKeyRotationStatus(ctx context.Context, c *kms.Client, keyId *string) (*bool, error) {
	output, err := c.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: keyId})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get key rotation status", zap.String("keyId", *keyId), zap.Error(err))
		return nil, err
	}
	return &output.KeyRotationEnabled, nil
}

// getKeyPolicy retrieves the policy for a key.
func getKeyPolicy(ctx context.Context, c *kms.Client, keyId *string) (map[string]interface{}, error) {
	output, err := c.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: keyId})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get key policy", zap.String("keyId", *keyId), zap.Error(err))
		return nil, err
	}

	var policy map[string]interface{}
	err = json.Unmarshal([]byte(*output.Policy), &policy)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to unmarshal key policy", zap.String("keyId", *keyId), zap.Error(err))
		return nil, err
	}
	return policy, nil
}

// listResourceTags retrieves all tags for a key.
func listResourceTags(ctx context.Context, c *kms.Client, keyId *string) ([]types.Tag, error) {
	var tags []types.Tag
	paginator := kms.NewListResourceTagsPaginator(c, &kms.ListResourceTagsInput{KeyId: keyId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list kms key tags", zap.String("keyId", *keyId), zap.Error(err))
			return nil, err
		}
		tags = append(tags, page.Tags...)
	}
	return tags, nil
}
