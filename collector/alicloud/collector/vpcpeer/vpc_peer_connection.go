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

package vpcpeer

import (
	"context"
	vpcpeer20220101 "github.com/alibabacloud-go/vpcpeer-20220101/v3/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/cloudrec/alicloud/collector/vpc"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetVpcPeerConnectionResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.VpcPeerConnection,
		ResourceTypeName:   "VPC Peer Connection",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/VpcPeer`,
		ResourceDetailFunc: GetVpcPeerConnectionDetail,
		RowField: schema.RowField{
			ResourceId:   "$.VpcPeerConnection.InstanceId",
			ResourceName: "$.VpcPeerConnection.Name",
		},
		Regions:   vpc.Regions,
		Dimension: schema.Regional,
	}
}

type PeerConnectionDetail struct {
	VpcPeerConnection *vpcpeer20220101.ListVpcPeerConnectionsResponseBodyVpcPeerConnects
	VpcPeerAttribute  *vpcpeer20220101.GetVpcPeerConnectionAttributeResponseBody
}

func GetVpcPeerConnectionDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VpcPeer

	request := &vpcpeer20220101.ListVpcPeerConnectionsRequest{}

	for {
		response, err := cli.ListVpcPeerConnections(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListVpcPeerConnections error", zap.Error(err))
			return err
		}

		for _, conn := range response.Body.VpcPeerConnects {
			// Get detailed connection attributes
			attribute := getVpcPeerConnectionAttribute(ctx, cli, conn.InstanceId)

			d := PeerConnectionDetail{
				VpcPeerConnection: conn,
				VpcPeerAttribute:  attribute,
			}

			res <- d
		}

		if response.Body.NextToken == nil || *response.Body.NextToken == "" {
			break
		}
		request.NextToken = response.Body.NextToken
	}

	return nil
}

func getVpcPeerConnectionAttribute(ctx context.Context, cli *vpcpeer20220101.Client, instanceId *string) *vpcpeer20220101.GetVpcPeerConnectionAttributeResponseBody {
	request := &vpcpeer20220101.GetVpcPeerConnectionAttributeRequest{
		InstanceId: instanceId,
	}

	response, err := cli.GetVpcPeerConnectionAttribute(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetVpcPeerConnectionAttribute error", zap.Error(err))
		return nil
	}

	return response.Body
}
