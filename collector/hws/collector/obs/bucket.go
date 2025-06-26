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

package obs

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"go.uber.org/zap"
)

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Bucket,
		ResourceTypeName:   "Bucket",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/OBS/doc?api=ListBuckets",
		ResourceDetailFunc: GetBucketDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Bucket.Name",
			ResourceName: "$.Bucket.Name",
		},
		Dimension: schema.Regional,
	}
}

type BucketDetail struct {
	Bucket                        obs.Bucket
	AccessControlPolicy           obs.AccessControlPolicy
	BucketEncryptionConfiguration obs.BucketEncryptionConfiguration
	BucketPolicy                  string
}

func GetBucketDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).OBS

	request := &obs.ListBucketsInput{}
	for {
		response, err := cli.ListBuckets(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListBuckets error", zap.Error(err))
			return err
		}

		for _, bucket := range response.Buckets {
			res <- &BucketDetail{
				Bucket:                        bucket,
				AccessControlPolicy:           getBucketAcl(ctx, cli, bucket.Name),
				BucketEncryptionConfiguration: getBucketEncryption(ctx, cli, bucket.Name),
				BucketPolicy:                  getBucketPolicy(ctx, cli, bucket.Name),
			}
		}

		if response.Buckets == nil || len(response.Buckets) == 0 || response.NextMarker == "" {
			break
		}

		request.Marker = response.NextMarker
	}
	return nil
}

func getBucketAcl(ctx context.Context, cli *obs.ObsClient, name string) (res obs.AccessControlPolicy) {
	response, err := cli.GetBucketAcl(name)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketAcl error", zap.Error(err))
		return
	}

	return response.AccessControlPolicy
}

func getBucketEncryption(ctx context.Context, cli *obs.ObsClient, name string) (res obs.BucketEncryptionConfiguration) {
	response, err := cli.GetBucketEncryption(name)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketEncryption error", zap.Error(err))
		return
	}

	return response.BucketEncryptionConfiguration
}

func getBucketPolicy(ctx context.Context, cli *obs.ObsClient, name string) (policy string) {
	response, err := cli.GetBucketPolicy(name)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetBucketPolicy error", zap.Error(err))
		return
	}

	return response.Policy
}
