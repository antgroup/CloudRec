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

package acl

import (
	"context"

	"github.com/baidubce/bce-sdk-go/services/vpc"
	"github.com/cloudrec/baidu/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// Detail embeds *vpc.ListAclEntrysResult so its fields (vpcId, vpcName,
// vpcCidr, aclEntrys) are promoted to the top level of the persisted JSON,
// matching the shape written by the legacy n8n pipeline. ResourceID and
// ResourceName carry the "acl-{vpcId}" prefix the n8n pipeline persisted
// into the resource_id / resource_name columns.
type Detail struct {
	*vpc.ListAclEntrysResult
	ResourceID   string `json:"resourceId"`
	ResourceName string `json:"resourceName"`
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.ACL,
		ResourceTypeName:  collector.ACL,
		ResourceGroupType: constant.NET,
		Desc:              `https://cloud.baidu.com/doc/VPC/s/Tjwvyuu64`,
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
		ResourceDetailFunc: ListAclResource,
		RowField: schema.RowField{
			ResourceId:   "$.resourceId",
			ResourceName: "$.resourceName",
		},
		Dimension: schema.Regional,
	}
}

// ListAclResource enumerates VPCs in the region and emits one ACL record per
// VPC (each carrying the full set of subnet ACL entries).
func ListAclResource(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).VPCClient

	args := &vpc.ListVPCArgs{}
	for {
		vpcResp, err := client.ListVPC(args)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListVPC error", zap.Error(err))
			return err
		}
		for _, v := range vpcResp.VPCs {
			aclResp, err := client.ListAclEntrys(v.VPCID)
			if err != nil {
				log.CtxLogger(ctx).Warn("ListAclEntrys error", zap.String("vpcId", v.VPCID), zap.Error(err))
				continue
			}
			res <- Detail{
				ListAclEntrysResult: aclResp,
				ResourceID:          "acl-" + v.VPCID,
				ResourceName:        "acl-" + v.Name,
			}
		}
		if vpcResp.NextMarker == "" {
			break
		}
		args.Marker = vpcResp.NextMarker
	}

	return nil
}
