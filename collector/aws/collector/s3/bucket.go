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

package s3

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetS3BucketResource returns a S3 Bucket Resource
func GetS3BucketResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Bucket,
		ResourceTypeName:   collector.Bucket,
		ResourceGroupType:  constant.STORE,
		Desc:               `https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html`,
		ResourceDetailFunc: GetBucketDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Bucket.Name",
			ResourceName: "$.Bucket.Name",
		},
		Dimension: schema.Regional,
	}
}

type BucketDetail struct {

	// The Bucket
	Bucket types.Bucket

	// Bucket Policy
	Policy map[string]interface{}

	// Versioning
	Versioning *s3.GetBucketVersioningOutput

	// LoggingEnabled
	LoggingEnabled *types.LoggingEnabled
}

func GetBucketDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).S3

	bucketDetails, err := describeBucketDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeBucketDetails error", zap.Error(err))
		return err
	}

	for _, bucketDetail := range bucketDetails {
		res <- bucketDetail
	}
	return nil
}

func describeBucketDetails(ctx context.Context, c *s3.Client) (bucketDetails []BucketDetail, err error) {
	buckets, err := listBuckets(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("listBuckets error", zap.Error(err))
		return nil, err
	}
	for _, bucket := range buckets {
		bucketDetails = append(bucketDetails, BucketDetail{
			Bucket:         bucket,
			Policy:         getBucketPolicy(ctx, c, bucket),
			Versioning:     getVersioning(ctx, c, bucket),
			LoggingEnabled: getLoggingEnabled(ctx, c, bucket),
		})
	}
	return bucketDetails, nil
}

func getLoggingEnabled(ctx context.Context, c *s3.Client, bucket types.Bucket) *types.LoggingEnabled {
	input := &s3.GetBucketLoggingInput{
		Bucket: bucket.Name,
	}
	output, err := c.GetBucketLogging(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("getLoggingEnabled error", zap.Error(err))
		return nil
	}
	return output.LoggingEnabled
}

func getVersioning(ctx context.Context, c *s3.Client, bucket types.Bucket) *s3.GetBucketVersioningOutput {
	input := &s3.GetBucketVersioningInput{Bucket: bucket.Name}
	output, err := c.GetBucketVersioning(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("getVersioning error", zap.Error(err))
		return nil
	}
	return output
}

func getBucketPolicy(ctx context.Context, c *s3.Client, bucket types.Bucket) (policy map[string]interface{}) {
	PolicyInput := &s3.GetBucketPolicyInput{Bucket: bucket.Name}
	PolicyOutput, err := c.GetBucketPolicy(ctx, PolicyInput)

	if err != nil {
		// cloud be NoSuchBucketPolicy error
		return nil
	}

	err = json.Unmarshal([]byte(*PolicyOutput.Policy), &policy)
	if err != nil {
		log.CtxLogger(ctx).Warn("getBucketPolicy error", zap.Error(err))
		return nil
	}
	return policy
}

func listBuckets(ctx context.Context, c *s3.Client) (buckets []types.Bucket, err error) {
	bucketRegion := c.Options().Region
	listBucketsInput := &s3.ListBucketsInput{
		BucketRegion: &bucketRegion,
	}
	listBucketsOutput, err := c.ListBuckets(ctx, listBucketsInput)
	if err != nil {
		log.CtxLogger(ctx).Warn("listBuckets error", zap.Error(err))
		return nil, err
	}
	buckets = append(buckets, listBucketsOutput.Buckets...)
	for listBucketsOutput.ContinuationToken != nil {
		listBucketsInput.ContinuationToken = listBucketsOutput.ContinuationToken
		listBucketsOutput, err = c.ListBuckets(ctx, listBucketsInput)
		if err != nil {
			log.CtxLogger(ctx).Warn("listBuckets error", zap.Error(err))
			return nil, err
		}
		buckets = append(buckets, listBucketsOutput.Buckets...)
	}

	return buckets, nil
}
