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
	"github.com/alicloud-sqa/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"encoding/json"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"go.uber.org/zap"
	"strings"
)

type BucketDetail struct {
	BucketProperties       *oss.BucketProperties
	BucketInfo             *oss.BucketInfo
	LoggingEnabled         *oss.LoggingEnabled
	BucketPolicy           interface{}
	SSEDefaultRule         *oss.SSEDefaultRule
	VersioningConfig       *oss.VersioningConfig
	RefererConfiguration   *oss.GetBucketRefererResult
	CORSConfiguration      *oss.GetBucketCORSResult
	InventoryConfiguration []oss.InventoryConfiguration
}

func GetOSSResource() schema.Resource {
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
	cli := service.(*collector.Services).OssClient

	pre := oss.Prefix("")
	marker := oss.Marker("")

	for {
		response, err := cli.ListBuckets(oss.MaxKeys(50), pre, marker)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListBuckets error", zap.Error(err))
			return err
		}
		for _, i := range response.Buckets {
			b := i
			d := &BucketDetail{
				BucketProperties:       &b,
				BucketInfo:             getBucketInfo(ctx, cli, b.Name),
				LoggingEnabled:         getBucketLogging(ctx, cli, b.Name),
				BucketPolicy:           getBucketPolicy(ctx, cli, b.Name),
				SSEDefaultRule:         getBucketEncryption(ctx, cli, b.Name),
				VersioningConfig:       getBucketVersioning(ctx, cli, b.Name),
				RefererConfiguration:   getBucketReferer(ctx, cli, b.Name),
				CORSConfiguration:      getBucketCORS(ctx, cli, b.Name),
				InventoryConfiguration: listBucketInventory(ctx, cli, b.Name),
			}
			res <- d
		}
		if !response.IsTruncated {
			break
		}
		pre = oss.Prefix(response.Prefix)
		marker = oss.Marker(response.NextMarker)
	}
	return nil
}

func removeSuffixFromLocation(location string) string {
	return strings.TrimPrefix(location, "oss-")
}

func createOssClient(region string, cli *oss.Client) (*oss.Client, error) {
	cli, err := oss.New("oss-"+region+".aliyuncs.com", cli.Config.AccessKeyID, cli.Config.AccessKeySecret)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

func getBucketInfo(ctx context.Context, cli *oss.Client, name string) (bucketInfo *oss.BucketInfo) {
RETRY:
	r, err := cli.GetBucketInfo(name)
	if err != nil {
		if se, ok := err.(oss.ServiceError); ok {
			ss := strings.Split(se.Endpoint, ".")
			if se.Endpoint != "" && len(ss) > 0 {
				location := ss[0]
				cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
				goto RETRY
			}
		}
		return
	}
	return &r.BucketInfo
}

// GetBucketLogging check Bucket logging config, Only the owner of the Bucket can view the logging config
func getBucketLogging(ctx context.Context, cli *oss.Client, name string) (loggingEnabled *oss.LoggingEnabled) {
RETRY:
	r, err := cli.GetBucketLogging(name)
	if err != nil {
		if se, ok := err.(oss.ServiceError); ok {
			ss := strings.Split(se.Endpoint, ".")
			if se.Endpoint != "" && len(ss) > 0 {
				location := ss[0]
				cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
				goto RETRY
			}
		}
		return
	}
	return &r.LoggingEnabled
}

func getBucketPolicy(ctx context.Context, cli *oss.Client, name string) (policy map[string]interface{}) {
RETRY:
	r, err := cli.GetBucketPolicy(name)
	if err != nil {
		if se, ok := err.(oss.ServiceError); ok {
			ss := strings.Split(se.Endpoint, ".")
			if se.Endpoint != "" && len(ss) > 0 {
				location := ss[0]
				cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
				goto RETRY
			}
		}
		return
	}

	data := make(map[string]interface{})
	err = json.Unmarshal([]byte(r), &data)
	return data
}

func getBucketEncryption(ctx context.Context, cli *oss.Client, name string) (SSEDefault *oss.SSEDefaultRule) {
RETRY:
	r, err := cli.GetBucketEncryption(name)
	if err != nil {
		if se, ok := err.(oss.ServiceError); ok {
			ss := strings.Split(se.Endpoint, ".")
			if se.Endpoint != "" && len(ss) > 0 {
				location := ss[0]
				cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
				goto RETRY
			}
		}
		return
	}
	return &r.SSEDefault
}

func getBucketVersioning(ctx context.Context, cli *oss.Client, name string) (versioningConfig *oss.VersioningConfig) {
RETRY:
	r, err := cli.GetBucketVersioning(name)
	if err != nil {
		if se, ok := err.(oss.ServiceError); ok {
			ss := strings.Split(se.Endpoint, ".")
			if se.Endpoint != "" && len(ss) > 0 {
				location := ss[0]
				cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
				goto RETRY
			}
		}
		return
	}
	config := oss.VersioningConfig(r)
	return &config
}

func getBucketReferer(ctx context.Context, cli *oss.Client, name string) *oss.GetBucketRefererResult {
RETRY:
	r, err := cli.GetBucketReferer(name)
	if err != nil {
		if se, ok := err.(oss.ServiceError); ok {
			ss := strings.Split(se.Endpoint, ".")
			if se.Endpoint != "" && len(ss) > 0 {
				location := ss[0]
				cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
				goto RETRY
			}
		}
		return nil
	}
	return &r
}

func getBucketCORS(ctx context.Context, cli *oss.Client, name string) *oss.GetBucketCORSResult {
RETRY:
	r, err := cli.GetBucketCORS(name)
	if err != nil {
		if se, ok := err.(oss.ServiceError); ok {
			ss := strings.Split(se.Endpoint, ".")
			if se.Endpoint != "" && len(ss) > 0 {
				location := ss[0]
				cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
				goto RETRY
			}
		}
		return nil
	}
	return &r
}

func listBucketInventory(ctx context.Context, cli *oss.Client, name string) (inventoryConfiguration []oss.InventoryConfiguration) {
RETRY:
	var continuationToken string = ""
	var isTruncated bool = true

	for isTruncated {
		r, err := cli.ListBucketInventory(name, continuationToken)
		if err != nil {
			if se, ok := err.(oss.ServiceError); ok {
				ss := strings.Split(se.Endpoint, ".")
				if se.Endpoint != "" && len(ss) > 0 {
					location := ss[0]
					cli, _ = createOssClient(removeSuffixFromLocation(location), cli)
					goto RETRY
				}
			}
			return nil
		}

		inventoryConfiguration = append(inventoryConfiguration, r.InventoryConfiguration...)
		isTruncated = *r.IsTruncated
		if isTruncated {
			continuationToken = r.NextContinuationToken
		}
	}

	return inventoryConfiguration
}
