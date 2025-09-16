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

package vpc

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetPhysicalConnectionResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.PhysicalConnection,
		ResourceTypeName:   "PhysicalConnection",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/Vpc`,
		ResourceDetailFunc: GetPhysicalConnectionDetail,
		RowField: schema.RowField{
			ResourceId:   "$.PhysicalConnection.PhysicalConnectionId",
			ResourceName: "$.PhysicalConnection.Name",
		},
		Dimension: schema.Regional,
	}
}

type PhysicalConnectionDetail struct {
	PhysicalConnection   vpc.PhysicalConnectionType
	VirtualBorderRouters []vpc.VirtualBorderRouterForPhysicalConnectionType
	AccessPoint          *vpc.AccessPointType
}

func GetPhysicalConnectionDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).VPC

	request := vpc.CreateDescribePhysicalConnectionsRequest()
	request.Scheme = "https"
	request.PageSize = requests.NewInteger(50)
	request.PageNumber = requests.NewInteger(1)

	for {
		response, err := cli.DescribePhysicalConnections(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribePhysicalConnections error", zap.Error(err))
			return err
		}

		for _, pc := range response.PhysicalConnectionSet.PhysicalConnectionType {
			// Get Virtual Border Routers for this physical connection
			vbrs := describeVirtualBorderRoutersForPhysicalConnection(ctx, cli, pc.PhysicalConnectionId)

			// Get Access Point details
			accessPoint := describeAccessPoint(ctx, cli, pc.AccessPointId)

			d := PhysicalConnectionDetail{
				PhysicalConnection:   pc,
				VirtualBorderRouters: vbrs,
				AccessPoint:          accessPoint,
			}
			res <- d
		}

		if response.PageNumber*response.PageSize >= response.TotalCount {
			break
		}
		request.PageNumber = requests.NewInteger(response.PageNumber + 1)
	}
	return nil
}

func describeVirtualBorderRoutersForPhysicalConnection(ctx context.Context, cli *vpc.Client, physicalConnectionID string) []vpc.VirtualBorderRouterForPhysicalConnectionType {
	request := vpc.CreateDescribeVirtualBorderRoutersForPhysicalConnectionRequest()
	request.Scheme = "https"
	request.PhysicalConnectionId = physicalConnectionID
	request.PageSize = requests.NewInteger(50)
	request.PageNumber = requests.NewInteger(1)

	var allVBRs []vpc.VirtualBorderRouterForPhysicalConnectionType

	for {
		response, err := cli.DescribeVirtualBorderRoutersForPhysicalConnection(request)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeVirtualBorderRoutersForPhysicalConnection error", zap.Error(err))
			return allVBRs
		}

		allVBRs = append(allVBRs, response.VirtualBorderRouterForPhysicalConnectionSet.VirtualBorderRouterForPhysicalConnectionType...)

		if len(allVBRs) >= response.TotalCount {
			break
		}
		request.PageNumber = requests.NewInteger(response.PageNumber + 1)
	}

	return allVBRs
}

func describeAccessPoint(ctx context.Context, cli *vpc.Client, accessPointID string) *vpc.AccessPointType {
	if accessPointID == "" {
		return nil
	}

	request := vpc.CreateDescribeAccessPointsRequest()
	request.Scheme = "https"
	request.PageSize = requests.NewInteger(10)
	request.PageNumber = requests.NewInteger(1)

	// Create filter for access point ID
	filterKey := "AccessPointId"
	filterValue := []string{accessPointID}
	request.Filter = &[]vpc.DescribeAccessPointsFilter{
		{
			Key:   filterKey,
			Value: &filterValue,
		},
	}

	response, err := cli.DescribeAccessPoints(request)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeAccessPoints error", zap.Error(err))
		return nil
	}

	if len(response.AccessPointSet.AccessPointType) > 0 {
		return &response.AccessPointSet.AccessPointType[0]
	}

	return nil
}
