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

package knad

import (
	"context"
	"encoding/json"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	kead "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kead/v20200101"
	knad "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/knad/v20230323"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"go.uber.org/zap"
	"strings"
)

type DescribeKeadResponse struct {
	RequestId string `json:"RequestId"`
	KeadSet   []any  `json:"KeadSet"`
}

type DescribeKnadResponse struct {
	RequestId string                   `json:"RequestId"`
	KnadSet   []map[string]interface{} `json:"KnadSet"`
}

type DescribeKnadIpResponse struct {
	RequestId   string `json:"RequestId"`
	KnadIpSet   []any  `json:"KnadIpSet"`
	KnadIpCount int    `json:"KnadIpCount"`
}

type Detail struct {
	Ddos any
	Eips []any
}

func GetKNADResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.KNAD,
		ResourceTypeName:  "DDos高防",
		ResourceGroupType: constant.SECURITY,
		Desc:              `https://apiexplorer.ksyun.com/#/document/documentList/0/1055`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			describeKNADResource(ctx, service.(*collector.Services).KNAD, res)
			describeKEADResource(ctx, service.(*collector.Services).KEAD, res)
			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.ResourceRecord.ResourceRecordId",
			ResourceName: "$.ResourceRecord.ResourceRecord",
		},
		Regions: []string{
			"cn-beijing-6", // 华北1（北京）
		},
		Dimension: schema.Global,
	}
}

func describeKEADResource(ctx context.Context, cli *kead.Client, res chan<- any) {
	request := kead.NewDescribeKeadRequest()

	responseStr := cli.DescribeKeadWithContext(ctx, request)
	collector.ShowResponse(ctx, "KEAD", "DescribeKead", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KEAD DescribeKead error", zap.Error(err))
		return
	}

	response := &DescribeKeadResponse{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KEAD DescribeKead decode error", zap.Error(err))
		return
	}

	if len(response.KeadSet) == 0 {
		return
	}

	for i := range response.KeadSet {
		res <- Detail{
			Ddos: response.KeadSet[i],
		}
	}
}

func describeKNADResource(ctx context.Context, cli *knad.Client, res chan<- any) {
	request := knad.NewDescribeKnadRequest()

	responseStr := cli.DescribeKnadWithContext(ctx, request)
	collector.ShowResponse(ctx, "KNAD", "DescribeKnad", responseStr)
	err := collector.CheckError(responseStr)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KNAD DescribeKnad error", zap.Error(err))
		return
	}

	response := &DescribeKnadResponse{}
	err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
	if err != nil {
		log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KNAD DescribeKnad decode error", zap.Error(err))
		return
	}
	if len(response.KnadSet) == 0 {
		return
	}
	for i := range response.KnadSet {
		id, ok := response.KnadSet[i]["KnadId"].(string)
		if ok {
			res <- Detail{
				Ddos: response.KnadSet[i],
				Eips: describeKnadIp(ctx, cli, id),
			}
			continue
		}
		res <- Detail{
			Ddos: response.KnadSet[i],
		}
	}
}

func describeKnadIp(ctx context.Context, cli *knad.Client, id string) (ans []any) {
	request := knad.NewDescribeKnadIpRequest()
	request.KnadId = common.StringPtr(id)
	request.PageSize = common.IntPtr(100)
	count := 0
	request.OffSet = common.IntPtr(count)

	for {
		responseStr := cli.DescribeKnadIpWithContext(ctx, request)
		collector.ShowResponse(ctx, "KNAD", "DescribeKnadIp", responseStr)
		err := collector.CheckError(responseStr)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KNAD DescribeKnadIp error", zap.Error(err))
			return nil
		}

		response := &DescribeKnadIpResponse{}
		err = json.NewDecoder(strings.NewReader(responseStr)).Decode(response)
		if err != nil {
			log.CtxLogger(ctx).With(zap.String("response", responseStr)).Warn("KNAD DescribeKnadIp decode error", zap.Error(err))
			return nil
		}
		if len(response.KnadIpSet) == 0 {
			return nil
		}

		for i := range response.KnadIpSet {
			ans = append(ans, response.KnadIpSet[i])
		}

		count += len(response.KnadIpSet)
		if count >= response.KnadIpCount {
			break
		}

		request.OffSet = common.IntPtr(count)
	}
	return ans
}
