// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ec2

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetNetworkInterfaceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.NetworkInterface,
		ResourceTypeName:   "Network Interface",
		ResourceGroupType:  constant.NET,
		Desc:               "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkInterfaces.html",
		ResourceDetailFunc: GetNetworkInterfaceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.NetworkInterfaceId",
			ResourceName: "$.NetworkInterfaceId",
		},
		Dimension: schema.Regional,
	}
}

type NetworkInterfaceDetail struct {
	NetworkInterface types.NetworkInterface
}

func GetNetworkInterfaceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EC2

	networkInterfaces, err := describeNetworkInterfaces(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe network interfaces", zap.Error(err))
		return err
	}

	for _, ni := range networkInterfaces {
		res <- NetworkInterfaceDetail{NetworkInterface: ni}
	}

	return nil
}

func describeNetworkInterfaces(ctx context.Context, c *ec2.Client) ([]types.NetworkInterface, error) {
	var networkInterfaces []types.NetworkInterface

	paginator := ec2.NewDescribeNetworkInterfacesPaginator(c, &ec2.DescribeNetworkInterfacesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		networkInterfaces = append(networkInterfaces, page.NetworkInterfaces...)
	}
	return networkInterfaces, nil
}
