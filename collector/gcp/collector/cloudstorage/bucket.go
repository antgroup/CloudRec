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

package cloudstorage

import (
	"context"
	"github.com/cloudrec/gcp/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/turbot/go-kit/types"
	"go.uber.org/zap"
	"google.golang.org/api/storage/v1"
)

func GetBucketResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.Bucket,
		ResourceTypeName:  collector.Bucket,
		ResourceGroupType: constant.STORE,
		Desc:              `https://cloud.google.com/storage/docs/apis`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			svc := service.(*collector.Services).StorageService
			projects := service.(*collector.Services).Projects

			for _, project := range projects {
				projectId := project.ProjectId
				maxResults := types.Int64(1000)
				resp := svc.Buckets.List(projectId).Projection("full").MaxResults(*maxResults)
				if err := resp.Pages(ctx, func(page *storage.Buckets) error {
					for _, bucket := range page.Items {
						d := BucketDetail{
							Bucket:         bucket,
							IamPolicy:      getBucketIamPolicy(ctx, svc, bucket.Name),
							ManagedFolders: getManagedFolders(ctx, svc, bucket.Name),
						}
						res <- d
					}
					return nil
				}); err != nil {
					log.CtxLogger(ctx).Warn("ListBuckets error", zap.Error(err))
					continue
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Bucket.id",
			ResourceName: "$.Bucket.name",
		},
		Dimension: schema.Global,
	}
}

type BucketDetail struct {
	Bucket         *storage.Bucket
	IamPolicy      *storage.Policy
	ManagedFolders []ManagedFolder
}

type ManagedFolder struct {
	Item      *storage.ManagedFolder
	IamPolicy *storage.Policy
}

func getBucketIamPolicy(ctx context.Context, storageService *storage.Service, bucketName string) *storage.Policy {
	iamPolicy, err := storageService.Buckets.GetIamPolicy(bucketName).Do()
	if err != nil {
		log.CtxLogger(ctx).Warn("getIamPolicy err", zap.Error(err))
		return nil
	}
	return iamPolicy
}

func getManagedFolders(ctx context.Context, storageService *storage.Service, bucketName string) (managedFolders []ManagedFolder) {
	resp, err := storageService.ManagedFolders.List(bucketName).Do()
	if err != nil {
		log.CtxLogger(ctx).Warn("getManagedFolders err", zap.Error(err))
		return nil
	}

	if resp == nil || resp.Items == nil {
		return nil
	}
	for _, managedFolder := range resp.Items {
		managedFolders = append(managedFolders, ManagedFolder{
			Item:      managedFolder,
			IamPolicy: getManagedFolderIamPolicy(ctx, storageService, bucketName, managedFolder.Name),
		})
	}
	return managedFolders
}

func getManagedFolderIamPolicy(ctx context.Context, service *storage.Service, bucket string, managedFolder string) *storage.Policy {
	policy, err := service.ManagedFolders.GetIamPolicy(bucket, managedFolder).Do()
	if err != nil {
		log.CtxLogger(ctx).Warn("getIamPolicy err", zap.Error(err))
		return nil
	}
	return policy
}
