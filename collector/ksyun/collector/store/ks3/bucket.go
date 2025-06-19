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

package ks3

import (
	"context"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/ks3sdklib/aws-sdk-go/aws/awsutil"
	"github.com/ks3sdklib/aws-sdk-go/service/s3"
	"go.uber.org/zap"
)

type Detail struct {
	Bucket        any
	Acl           any
	BucketLogging any
}

func GetKS3Resource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KS3,
		ResourceTypeName:  collector.KS3,
		ResourceGroupType: constant.STORE,
		Desc:              `https://docs.ksyun.com/documents/41266?type=3`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).KS3
			response, err := cli.ListBucketsWithContext(ctx, &s3.ListBucketsInput{})
			collector.ShowResponse(ctx, collector.KS3, "ListBuckets", awsutil.StringValue(response))
			if err != nil {
				log.CtxLogger(ctx).Warn("KS3 ListBuckets error", zap.Error(err))
				return err
			}

			if len(response.Buckets) == 0 {
				return nil
			}

			for i := range response.Buckets {
				res <- &Detail{
					Bucket:        &response.Buckets[i],
					Acl:           getBucketAcl(ctx, cli, response.Buckets[i].Name),
					BucketLogging: getBucketLogging(ctx, cli, response.Buckets[i].Name),
				}
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Bucket.Name",
			ResourceName: "$.Bucket.Name",
		},
		Regions: []string{
			"BEIJING",     // 中国（北京）
			"SHANGHAI",    // 中国（上海）
			"GUANGZHOU",   // 中国（广州）
			"SINGAPORE",   // 新加坡
			"JR_SHANGHAI", // 金融专区（上海）
			"JR_BEIJING",  // 金融专区（北京）
		},
		Dimension: schema.Global,
	}
}

func getBucketAcl(ctx context.Context, cli *s3.S3, bucket *string) any {
	acl, err := cli.GetBucketACLWithContext(ctx, &s3.GetBucketACLInput{Bucket: bucket})
	if err != nil {
		log.CtxLogger(ctx).Warn("KS3 GetBucketACL error", zap.Error(err))
		return nil
	}
	return acl
}

func getBucketLogging(ctx context.Context, cli *s3.S3, bucket *string) any {
	loggging, err := cli.GetBucketLoggingWithContext(ctx, &s3.GetBucketLoggingInput{Bucket: bucket})
	if err != nil {
		log.CtxLogger(ctx).Warn("KS3 GetBucketLogging error", zap.Error(err))
		return nil
	}
	return loggging
}
