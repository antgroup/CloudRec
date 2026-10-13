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

package eni

import (
	"context"

	"github.com/baidubce/bce-sdk-go/services/eni"
	"github.com/baidubce/bce-sdk-go/services/vpc"
	"github.com/cloudrec/baidu/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// Detail is a flat alias of eni.Eni so the persisted JSON keeps the API's
// top-level field names ($.eniId, $.name, $.privateIpSet, ...). This matches
// the shape produced by the legacy n8n pipeline, so JSONPath expressions
// already in use against existing records keep working.
type Detail = eni.Eni

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.ENI,
		ResourceTypeName:  collector.ENI,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.baidu.com/doc/VPC/s/0jwvytu2v`,
		Regions: []string{
			"bcc.bj.baidubce.com",
			"bcc.gz.baidubce.com",
			"bcc.su.baidubce.com",
			"bcc.hkg.baidubce.com",
			"bcc.fwh.baidubce.com",
			"bcc.bd.baidubce.com",
			"bcc.cd.baidubce.com",
			"bcc.fsh.baidubce.com",
		},
		ResourceDetailFunc: ListEniResource,
		RowField: schema.RowField{
			ResourceId:   "$.eniId",
			ResourceName: "$.name",
			Address:      "$.privateIpSet[0].publicIpAddress",
		},
		Dimension: schema.Regional,
	}
}

// ListEniResource lists ALL ENIs in a region by first enumerating VPCs and
// then calling ListEni per VPC (the baidu ListEni API requires a vpcId).
// This captures unattached ENIs and ENIs attached to non-BCC resources.
func ListEniResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	vpcClient := service.(*collector.Services).VPCClient
	eniClient := service.(*collector.Services).ENIClient

	vpcArgs := &vpc.ListVPCArgs{}
	for {
		vpcResp, err := vpcClient.ListVPC(vpcArgs)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListVPC error", zap.Error(err))
			return err
		}
		for _, v := range vpcResp.VPCs {
			eniArgs := &eni.ListEniArgs{VpcId: v.VPCID}
			for {
				eniResp, err := eniClient.ListEni(eniArgs)
				if err != nil {
					log.CtxLogger(ctx).Warn("ListEni error", zap.String("vpcId", v.VPCID), zap.Error(err))
					break
				}
				for i := range eniResp.Eni {
					res <- eniResp.Eni[i]
				}
				if !eniResp.IsTruncated || eniResp.NextMarker == "" {
					break
				}
				eniArgs.Marker = eniResp.NextMarker
			}
		}
		if vpcResp.NextMarker == "" {
			break
		}
		vpcArgs.Marker = vpcResp.NextMarker
	}

	return nil
}
