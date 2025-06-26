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

package cos

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"fmt"
	"github.com/cloudrec/tencent/collector"
	"github.com/tencentyun/cos-go-sdk-v5"
	"go.uber.org/zap"
	"net/url"
)

func GetBucketResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Bucket,
		ResourceTypeName:   "Bucket",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://cloud.tencent.com/document/product/436",
		ResourceDetailFunc: ListBucketResource,
		RowField: schema.RowField{
			ResourceId:   "$.Bucket.Name",
			ResourceName: "$.Bucket.Name",
		},
		Dimension: schema.Global,
	}
}

type Detail struct {
	Bucket             cos.Bucket
	BucketGetACLResult cos.BucketGetACLResult
	BucketLogging      cos.BucketGetLoggingResult
	Versioning         cos.BucketGetVersionResult
}

func ListBucketResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).COS

	resp, _, err := cli.Service.Get(context.Background())
	if err != nil {
		log.CtxLogger(ctx).Warn("ListBucketResource error", zap.Error(err))
		return err
	}

	for _, bucket := range resp.Buckets {
		fmt.Printf("%+v\n", bucket)
		d := &Detail{
			Bucket:             bucket,
			BucketGetACLResult: getBucketAcl(ctx, cli, bucket),
			BucketLogging:      getBucketLogging(ctx, cli, bucket),
			Versioning:         getBucketVersioning(ctx, cli, bucket),
		}

		res <- d
	}

	return nil
}

func getBucketVersioning(ctx context.Context, cli *cos.Client, bucket cos.Bucket) cos.BucketGetVersionResult {
	u, _ := url.Parse(fmt.Sprintf("https://%s.cos.%s.myqcloud.com", bucket.Name, bucket.Region))
	cli.BaseURL.BucketURL = u

	res, _, err := cli.Bucket.GetVersioning(context.Background())
	if err != nil {
		log.CtxLogger(ctx).Warn("GetVersioning error", zap.Error(err))
	}
	return *res
}

func getBucketLogging(ctx context.Context, cli *cos.Client, bucket cos.Bucket) cos.BucketGetLoggingResult {
	u, _ := url.Parse(fmt.Sprintf("https://%s.cos.%s.myqcloud.com", bucket.Name, bucket.Region))
	cli.BaseURL.BucketURL = u

	res, _, err := cli.Bucket.GetLogging(context.Background())
	if err != nil {
		log.CtxLogger(ctx).Warn("GetLogging error", zap.Error(err))
	}
	return *res
}

func getBucketAcl(ctx context.Context, cli *cos.Client, bucket cos.Bucket) (BucketGetACLResult cos.BucketGetACLResult) {
	u, _ := url.Parse(fmt.Sprintf("https://%s.cos.%s.myqcloud.com", bucket.Name, bucket.Region))
	cli.BaseURL.BucketURL = u

	res, _, err := cli.Bucket.GetACL(context.Background())
	if err != nil {
		log.CtxLogger(ctx).Warn("GetACL error", zap.Error(err))
	}

	return *res
}
