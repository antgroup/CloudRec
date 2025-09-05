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

package cloudstoragegateway

import (
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sgw"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetCloudStorageGatewayResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudStorageGateway,
		ResourceTypeName:   "CloudStorageGateway",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/product/sgw`,
		ResourceDetailFunc: GetCloudStorageGatewayDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Gateway.GatewayId",
			ResourceName: "$.Gateway.Name",
		},
		Dimension: schema.Global,
	}
}

type CloudStorageGatewayDetail struct {
	Gateway      sgw.Gateway
	AuthInfo     *sgw.DescribeGatewayAuthInfoResponse
	FileShares   []sgw.FileShare
	BlockVolumes []sgw.BlockVolume
	SMBUsers     []sgw.User
	NFSClients   []sgw.ClientInfo
	LDAPInfo     *sgw.DescribeGatewayLDAPInfoResponse
}

func GetCloudStorageGatewayDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).SGW

	describeGatewaysRequest := sgw.CreateDescribeGatewaysRequest()
	describeGatewaysRequest.Scheme = "https"
	describeGatewaysRequest.PageSize = requests.NewInteger(100)
	describeGatewaysRequest.PageNumber = requests.NewInteger(1)

	for {
		response, err := cli.DescribeGateways(describeGatewaysRequest)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeGateways error", zap.Error(err))
			return err
		}

		if len(response.Gateways.Gateway) == 0 {
			break
		}

		for _, gateway := range response.Gateways.Gateway {
			authInfo := getGatewayAuthInfo(ctx, cli, gateway.GatewayId)
			fileShares := getGatewayFileShares(ctx, cli, gateway.GatewayId)
			blockVolumes := getGatewayBlockVolumes(ctx, cli, gateway.GatewayId)
			smbUsers := getGatewaySMBUsers(ctx, cli, gateway.GatewayId)
			nfsClients := getGatewayNFSClients(ctx, cli, gateway.GatewayId)
			ldapInfo := getGatewayLDAPInfo(ctx, cli, gateway.GatewayId)

			d := CloudStorageGatewayDetail{
				Gateway:      gateway,
				AuthInfo:     authInfo,
				FileShares:   fileShares,
				BlockVolumes: blockVolumes,
				SMBUsers:     smbUsers,
				NFSClients:   nfsClients,
				LDAPInfo:     ldapInfo,
			}

			res <- d
		}

		// Check if there are more pages
		totalCount := response.TotalCount
		pageSize := describeGatewaysRequest.PageSize
		pageNumber := describeGatewaysRequest.PageNumber

		pageNum, _ := pageNumber.GetValue()
		pageSizeNum, _ := pageSize.GetValue()
		totalNum := totalCount

		if pageNum*pageSizeNum >= totalNum {
			break
		}

		describeGatewaysRequest.PageNumber = requests.NewInteger(pageNum + 1)
	}

	return nil
}

func getGatewayAuthInfo(ctx context.Context, cli *sgw.Client, gatewayId string) *sgw.DescribeGatewayAuthInfoResponse {
	describeGatewayAuthInfoRequest := sgw.CreateDescribeGatewayAuthInfoRequest()
	describeGatewayAuthInfoRequest.Scheme = "https"
	describeGatewayAuthInfoRequest.GatewayId = gatewayId

	response, err := cli.DescribeGatewayAuthInfo(describeGatewayAuthInfoRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeGatewayAuthInfo error", zap.Error(err), zap.String("gatewayId", gatewayId))
		return nil
	}

	return response
}

func getGatewayFileShares(ctx context.Context, cli *sgw.Client, gatewayId string) []sgw.FileShare {
	describeGatewayFileSharesRequest := sgw.CreateDescribeGatewayFileSharesRequest()
	describeGatewayFileSharesRequest.Scheme = "https"
	describeGatewayFileSharesRequest.GatewayId = gatewayId

	response, err := cli.DescribeGatewayFileShares(describeGatewayFileSharesRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeGatewayFileShares error", zap.Error(err), zap.String("gatewayId", gatewayId))
		return []sgw.FileShare{}
	}

	return response.FileShares.FileShare
}

func getGatewayBlockVolumes(ctx context.Context, cli *sgw.Client, gatewayId string) []sgw.BlockVolume {
	describeGatewayBlockVolumesRequest := sgw.CreateDescribeGatewayBlockVolumesRequest()
	describeGatewayBlockVolumesRequest.Scheme = "https"
	describeGatewayBlockVolumesRequest.GatewayId = gatewayId

	response, err := cli.DescribeGatewayBlockVolumes(describeGatewayBlockVolumesRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeGatewayBlockVolumes error", zap.Error(err), zap.String("gatewayId", gatewayId))
		return []sgw.BlockVolume{}
	}

	return response.BlockVolumes.BlockVolume
}

func getGatewaySMBUsers(ctx context.Context, cli *sgw.Client, gatewayId string) []sgw.User {
	describeGatewaySMBUsersRequest := sgw.CreateDescribeGatewaySMBUsersRequest()
	describeGatewaySMBUsersRequest.Scheme = "https"
	describeGatewaySMBUsersRequest.GatewayId = gatewayId

	response, err := cli.DescribeGatewaySMBUsers(describeGatewaySMBUsersRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeGatewaySMBUsers error", zap.Error(err), zap.String("gatewayId", gatewayId))
		return []sgw.User{}
	}

	return response.Users.User
}

func getGatewayNFSClients(ctx context.Context, cli *sgw.Client, gatewayId string) []sgw.ClientInfo {
	describeGatewayNFSClientsRequest := sgw.CreateDescribeGatewayNFSClientsRequest()
	describeGatewayNFSClientsRequest.Scheme = "https"
	describeGatewayNFSClientsRequest.GatewayId = gatewayId

	response, err := cli.DescribeGatewayNFSClients(describeGatewayNFSClientsRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeGatewayNFSClients error", zap.Error(err), zap.String("gatewayId", gatewayId))
		return []sgw.ClientInfo{}
	}

	return response.ClientInfoList.ClientInfo
}

func getGatewayLDAPInfo(ctx context.Context, cli *sgw.Client, gatewayId string) *sgw.DescribeGatewayLDAPInfoResponse {
	describeGatewayLDAPInfoRequest := sgw.CreateDescribeGatewayLDAPInfoRequest()
	describeGatewayLDAPInfoRequest.Scheme = "https"
	describeGatewayLDAPInfoRequest.GatewayId = gatewayId

	response, err := cli.DescribeGatewayLDAPInfo(describeGatewayLDAPInfoRequest)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeGatewayLDAPInfo error", zap.Error(err), zap.String("gatewayId", gatewayId))
		return nil
	}

	return response
}
