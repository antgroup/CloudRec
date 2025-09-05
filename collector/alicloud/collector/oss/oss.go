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

package oss

import (
	"context"
	"encoding/json"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	ossCredentials "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

type BucketDetail struct {
	BucketProperties       oss.BucketProperties
	BucketInfo             *oss.BucketInfo
	LoggingEnabled         *oss.LoggingEnabled
	BucketPolicy           interface{}
	SSEDefaultRule         *oss.ApplyServerSideEncryptionByDefault
	VersioningConfig       *string
	RefererConfiguration   *oss.RefererConfiguration
	CORSConfiguration      *oss.CORSConfiguration
	InventoryConfiguration []oss.InventoryConfiguration
}

func GetBucketResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.OSS,
		ResourceTypeName:   collector.OSS,
		ResourceGroupType:  constant.STORE,
		Desc:               "https://api.aliyun.com/product/Oss",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.BucketProperties.Name",
			ResourceName: "$.BucketProperties.Name",
		},
		Dimension: schema.Global,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).OSS
	config := service.(*collector.Services).Config
	p := cli.NewListBucketsPaginator(&oss.ListBucketsRequest{
		MaxKeys: 200,
	})
	var i int
	for p.HasNext() {
		i++

		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}

		// Since ListBuckets returns all buckets in regions,
		// and other apis can't be invoked across regions.
		regionBuckets := make(map[string][]oss.BucketProperties)
		for _, bucket := range page.Buckets {
			regionBuckets[*bucket.Region] = append(regionBuckets[*bucket.Region], bucket)
		}

		for region, buckets := range regionBuckets {
			cli = createOSSClient(region, config)
			for _, bucket := range buckets {
				d := &BucketDetail{
					BucketProperties:       bucket,
					BucketInfo:             getBucketInfo(ctx, cli, bucket.Name),
					LoggingEnabled:         getBucketLogging(ctx, cli, bucket.Name),
					BucketPolicy:           getBucketPolicy(ctx, cli, bucket.Name),
					SSEDefaultRule:         getBucketEncryption(ctx, cli, bucket.Name),
					VersioningConfig:       getBucketVersioning(ctx, cli, bucket.Name),
					RefererConfiguration:   getBucketReferer(ctx, cli, bucket.Name),
					CORSConfiguration:      getBucketCORS(ctx, cli, bucket.Name),
					InventoryConfiguration: listBucketInventory(ctx, cli, bucket.Name),
				}
				res <- d
			}
		}
	}

	return nil
}

func createOSSClient(region string, config *openapi.Config) *oss.Client {
	cfg := oss.LoadDefaultConfig().
		WithCredentialsProvider(ossCredentials.NewStaticCredentialsProvider(*config.AccessKeyId, *config.AccessKeySecret)).
		WithRegion(region)

	return oss.NewClient(cfg)
}

func getBucketInfo(ctx context.Context, cli *oss.Client, name *string) (bucketInfo *oss.BucketInfo) {
	request := &oss.GetBucketInfoRequest{
		Bucket: name,
	}
	r, err := cli.GetBucketInfo(ctx, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketInfo error", zap.Error(err))
		return
	}
	return &r.BucketInfo
}

// GetBucketLogging check Bucket logging config, Only the owner of the Bucket can view the logging config
func getBucketLogging(ctx context.Context, cli *oss.Client, name *string) (loggingEnabled *oss.LoggingEnabled) {
	request := &oss.GetBucketLoggingRequest{
		Bucket: name,
	}
	r, err := cli.GetBucketLogging(ctx, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketLogging error", zap.Error(err))
		return
	}
	return r.BucketLoggingStatus.LoggingEnabled
}

func getBucketPolicy(ctx context.Context, cli *oss.Client, name *string) (policy map[string]interface{}) {
	request := &oss.GetBucketPolicyRequest{
		Bucket: name,
	}
	r, err := cli.GetBucketPolicy(ctx, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketPolicy error", zap.Error(err))
		return
	}

	data := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.Body), &data)
	if err != nil {
		log.CtxLogger(ctx).Warn("Unmarshal Bucket Policy error", zap.Error(err))
		return
	}
	return data
}

func getBucketEncryption(ctx context.Context, cli *oss.Client, name *string) (SSEDefault *oss.ApplyServerSideEncryptionByDefault) {
	request := &oss.GetBucketEncryptionRequest{
		Bucket: name,
	}
	r, err := cli.GetBucketEncryption(ctx, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketEncryption error", zap.Error(err))
		return
	}
	return r.ServerSideEncryptionRule.ApplyServerSideEncryptionByDefault
}

func getBucketVersioning(ctx context.Context, cli *oss.Client, name *string) (versioningConfig *string) {
	request := &oss.GetBucketVersioningRequest{
		Bucket: name,
	}
	r, err := cli.GetBucketVersioning(ctx, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketVersioning error", zap.Error(err))
		return
	}
	return r.VersionStatus
}

func getBucketReferer(ctx context.Context, cli *oss.Client, name *string) *oss.RefererConfiguration {
	request := &oss.GetBucketRefererRequest{
		Bucket: name,
	}
	r, err := cli.GetBucketReferer(ctx, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketReferer error", zap.Error(err))
		return nil
	}
	return r.RefererConfiguration
}

func getBucketCORS(ctx context.Context, cli *oss.Client, name *string) (bucketCORSResult *oss.CORSConfiguration) {
	request := &oss.GetBucketCorsRequest{
		Bucket: name,
	}
	r, err := cli.GetBucketCors(ctx, request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketCORS error", zap.Error(err))
		return
	}
	return r.CORSConfiguration
}

func listBucketInventory(ctx context.Context, cli *oss.Client, name *string) (inventoryConfiguration []oss.InventoryConfiguration) {
	var continuationToken *string
	var isTruncated = true
	for isTruncated {
		request := &oss.ListBucketInventoryRequest{
			Bucket:            name,
			ContinuationToken: continuationToken,
		}
		r, err := cli.ListBucketInventory(ctx, request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListBucketInventory error", zap.Error(err))
			return nil
		}

		inventoryConfiguration = append(inventoryConfiguration, r.ListInventoryConfigurationsResult.InventoryConfigurations...)
		isTruncated = *r.ListInventoryConfigurationsResult.IsTruncated
		if isTruncated {
			continuationToken = r.ListInventoryConfigurationsResult.NextContinuationToken
		}
	}

	return inventoryConfiguration
}
