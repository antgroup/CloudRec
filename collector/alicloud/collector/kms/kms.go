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
	"fmt"
	"go.uber.org/zap"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kms20160120 "github.com/alibabacloud-go/kms-20160120/v3/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
)

func GetKMSResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.KMS,
		ResourceTypeName:   "KMS",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://api.aliyun.com/product/Kms",
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.ResourceId",
			ResourceName: "$.ResourceName",
		},
		Regions: []string{"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-huhehaote",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-fuzhou",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"cn-wuhan-lr",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-zhengzhou-jva",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"na-south-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
			"cn-beijing-finance-1",
			"cn-hangzhou-finance",
			"cn-shanghai-finance-1",
			"cn-shenzhen-finance-1",
			"cn-heyuan-acdr-1",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	cli := services.KMS

	listKmsInstancesRequest := &kms20160120.ListKmsInstancesRequest{}
	runtime := &util.RuntimeOptions{}
	instance, err := cli.ListKmsInstancesWithOptions(listKmsInstancesRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListKmsInstancesWithOptions error", zap.Error(err))
		return err
	}

	// If the region has no scaling group, skip subsequent queries
	if len(instance.Body.KmsInstances.KmsInstance) == 0 {
		return nil
	}

	res <- Detail{
		RegionId:     *cli.RegionId,
		ResourceId:   fmt.Sprintf("%s_%s", *cli.RegionId, services.CloudAccountId),
		ResourceName: fmt.Sprintf("kms_%s_%s", *cli.RegionId, services.CloudAccountId),
		Instance:     instance.Body.KmsInstances.KmsInstance,
		Key:          describeKey(ctx, cli),
		Secret:       describeSecret(ctx, cli),
	}
	return nil
}

type Detail struct {
	// Region
	RegionId string

	ResourceId string

	ResourceName string

	// Instance information
	Instance []*kms20160120.ListKmsInstancesResponseBodyKmsInstancesKmsInstance

	// Key information
	Key []*kms20160120.DescribeKeyResponseBodyKeyMetadata

	// Credential information
	Secret []*kms20160120.DescribeSecretResponseBody
}

// Get the master key information
func describeKey(ctx context.Context, cli *kms20160120.Client) []*kms20160120.DescribeKeyResponseBodyKeyMetadata {
	// Get all master key IDs
	listKeysRequest := &kms20160120.ListKeysRequest{}
	runtime := &util.RuntimeOptions{}

	keys, err := cli.ListKeysWithOptions(listKeysRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListKeysWithOptions error", zap.Error(err))
		return nil
	}

	// Query information about the master key
	var result []*kms20160120.DescribeKeyResponseBodyKeyMetadata
	for _, key := range keys.Body.Keys.Key {
		describeKeyRequest := &kms20160120.DescribeKeyRequest{
			KeyId: tea.String(*key.KeyId),
		}
		runtime := &util.RuntimeOptions{}

		keyDetail, err := cli.DescribeKeyWithOptions(describeKeyRequest, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeKeyWithOptions error", zap.Error(err))
			return nil
		}
		result = append(result, keyDetail.Body.KeyMetadata)
	}
	return result
}

// Obtain the credential information
func describeSecret(ctx context.Context, cli *kms20160120.Client) []*kms20160120.DescribeSecretResponseBody {
	// Get all the credentials
	listSecretsRequest := &kms20160120.ListSecretsRequest{}
	runtime := &util.RuntimeOptions{}

	secrets, err := cli.ListSecretsWithOptions(listSecretsRequest, runtime)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListSecretsWithOptions error", zap.Error(err))
		return nil
	}

	// Query the credential details
	var result []*kms20160120.DescribeSecretResponseBody
	for _, secret := range secrets.Body.SecretList.Secret {
		describeSecretRequest := &kms20160120.DescribeSecretRequest{
			SecretName: tea.String(*secret.SecretName),
		}
		runtime := &util.RuntimeOptions{}

		secretDetail, err := cli.DescribeSecretWithOptions(describeSecretRequest, runtime)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeSecretWithOptions error", zap.Error(err))
			return nil
		}
		result = append(result, secretDetail.Body)
	}
	return result
}
