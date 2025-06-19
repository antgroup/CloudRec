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

package cdn

import (
	"context"
	"encoding/json"
	cdn "github.com/KscSDK/ksc-sdk-go/service/cdnv1"
	"github.com/cloudrec/ksyun/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

type Domain struct {
	DomainName      string `json:"DomainName"`      // www.test.com.hdlvcloud.ks-cdn.com	加速域名名称
	DomainId        string `json:"DomainId"`        // 2D074NB	域名ID
	Cname           string `json:"Cname"`           // example.ksc-test.com.download.ks-cdn.com	加速域名对应的CNAME域名
	CdnType         string `json:"CdnType"`         // wcdn	产品类型：file：大文件下载，video：音视频点播，page：图片小文件，live：流媒体直播
	IcpRegistration string `json:"IcpRegistration"` // 京ICP备10000000号-11	ICP备案号
	DomainStatus    string `json:"DomainStatus"`    // online	加速域名状态，具体枚举类型表见使用须知
	CreatedTime     string `json:"CreatedTime"`     // 2021-10-25T11:03+0800	加速域名创建时间
	ModifiedTime    string `json:"ModifiedTime"`    //	2021-10-25T11:03+0800	加速域名最近修改时间
	Description     string `json:"Description"`     // -	审核失败原因，正常情况下为空
	Region          string `json:"Region"`          // CN	域名的服务区域，具体枚举类型表见使用须知
}

type GetDomainResponse struct {
	PageNumber int      `json:"PageNumber"`
	PageSize   int      `json:"PageSize"`
	TotalCount int      `json:"TotalCount"`
	Domains    []Domain `json:"Domains"`
}

type Detail struct {
	Domain  any
	Configs *map[string]interface{}
}

func GetCDNResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.CDN,
		ResourceTypeName:  collector.CDN,
		ResourceGroupType: constant.NET,
		Desc:              `https://docs.ksyun.com/documents/195?type=3`,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			cli := service.(*collector.Services).CDN
			getCdnDomainReq := make(map[string]interface{})
			page := 1
			count := 0
			getCdnDomainReq["PageSize"] = 100
			getCdnDomainReq["PageNumber"] = page

			for {
				responsePtr, err := cli.GetCdnDomainsGetWithContext(ctx, &getCdnDomainReq)
				if err != nil || responsePtr == nil {
					log.CtxLogger(ctx).Warn("CDN GetCdnDomains error", zap.Error(err))
					return err
				}
				str, _ := json.Marshal(responsePtr)
				collector.ShowResponse(ctx, "CDN", "GetCdnDomains", string(str))

				response := &GetDomainResponse{}
				err = json.Unmarshal(str, &response)
				if err != nil {
					log.CtxLogger(ctx).Warn("CDN GetCdnDomains decode error", zap.Error(err))
					return err
				}
				if len(response.Domains) == 0 {
					break
				}

				for i := range response.Domains {
					res <- &Detail{
						Domain:  response.Domains[i],
						Configs: getDomainConfigs(ctx, cli, response.Domains[i].DomainId),
					}
				}
				count += len(response.Domains)
				if count >= response.TotalCount {
					break
				}
				page++
				getCdnDomainReq["PageNumber"] = page
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Domain.DomainId",
			ResourceName: "$.Domain.DomainName",
		},
		Regions: []string{
			"cn-beijing-6",  // 华北1（北京）
			"cn-shanghai-2", // 华东1（上海）
			"cn-hongkong-2", // 香港
		},
		Dimension: schema.Regional,
	}
}

func getDomainConfigs(ctx context.Context, cli *cdn.Cdnv1, domainId string) *map[string]interface{} {
	getDomainReq := make(map[string]interface{})
	getDomainReq["DomainId"] = domainId

	responsePtr, err := cli.GetDomainConfigsGetWithContext(ctx, &getDomainReq)
	if err != nil {
		log.CtxLogger(ctx).Warn("CDN GetDomainConfigs error", zap.Error(err))
		return nil
	}
	return responsePtr
}
