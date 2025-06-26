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

package cbr

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/cloudrec/hws/collector"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cbr/v1/model"
	"go.uber.org/zap"
)

func GetVaultResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CBR,
		ResourceTypeName:   "CBR Vault",
		ResourceGroupType:  constant.STORE,
		Desc:               "https://console.huaweicloud.com/apiexplorer/#/openapi/CBR/sdk?api=ListVault",
		ResourceDetailFunc: GetVaultDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Vault.id",
			ResourceName: "$.Vault.name",
		},
		Dimension: schema.Regional,
	}
}

type VaultDetail struct {
	Vault model.Vault
}

func GetVaultDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).CBR

	limit := int32(50)
	offset := int32(0)
	request := &model.ListVaultRequest{
		Limit:  &limit,
		Offset: &offset,
	}
	for {
		response, err := cli.ListVault(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListVault error", zap.Error(err))
			return err
		}

		for _, vault := range *response.Vaults {
			res <- &VaultDetail{
				Vault: vault,
			}
		}

		if len(*response.Vaults) < int(limit) {
			break
		}

		*request.Offset = *request.Offset + 1
	}
	return nil
}
