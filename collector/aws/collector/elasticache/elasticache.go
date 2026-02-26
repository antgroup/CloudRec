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

package elasticache

import (
	"context"
	ec2Sdk "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/cloudrec/aws/collector"
	"github.com/cloudrec/aws/collector/ec2"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"strings"
)

// GetElastiCacheClusterResource returns a ElastiCacheCluster Resource
func GetElastiCacheClusterResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ElastiCache,
		ResourceTypeName:   "ElastiCache",
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeCacheClusters.html`,
		ResourceDetailFunc: GetCacheClusterDetail,
		RowField: schema.RowField{
			ResourceId:   "$.CacheCluster.CacheClusterId",
			ResourceName: "$.CacheCluster.CacheClusterId",
		},
		Dimension: schema.Regional,
	}
}

type CacheClusterDetail struct {
	CacheCluster types.CacheCluster
	// SecurityGroups includes detailed ingress/egress rules for linked VPC security groups.
	SecurityGroups  []ec2.SecurityGroupDetail
	NetworkExposure ClusterNetworkExposure
}

type ClusterNetworkExposure struct {
	CacheSubnetGroupName     string
	SubnetIDs                []string
	VpcID                    string
	HasPublicSubnet          bool
	HasInternetGatewayRoute  bool
	HasEgressOnlyGatewayIPv6 bool
}

func GetCacheClusterDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	elasticacheClient := services.ElastiCache
	ec2Client := services.EC2

	cacheClusterDetails, err := describeCacheClusterDetails(ctx, elasticacheClient, ec2Client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeCacheClusterDetails error", zap.Error(err))
		return err
	}

	for _, cacheClusterDetail := range cacheClusterDetails {
		res <- cacheClusterDetail
	}
	return nil
}

func describeCacheClusterDetails(ctx context.Context, c *elasticache.Client, ec2Client *ec2Sdk.Client) (cacheClusterDetails []CacheClusterDetail, err error) {
	cacheClusters, err := describeCacheClusters(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeCacheClusters error", zap.Error(err))
		return nil, err
	}
	for _, cacheCluster := range cacheClusters {
		securityGroups := describeClusterSecurityGroups(ctx, ec2Client, cacheCluster.SecurityGroups)
		networkExposure := describeClusterNetworkExposure(ctx, c, ec2Client, cacheCluster.CacheSubnetGroupName)
		cacheClusterDetails = append(cacheClusterDetails, CacheClusterDetail{
			CacheCluster:    cacheCluster,
			SecurityGroups:  securityGroups,
			NetworkExposure: networkExposure,
		})
	}

	return cacheClusterDetails, nil
}

func describeClusterSecurityGroups(ctx context.Context, ec2Client *ec2Sdk.Client, groups []types.SecurityGroupMembership) []ec2.SecurityGroupDetail {
	if ec2Client == nil || len(groups) == 0 {
		return nil
	}

	groupIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		if group.SecurityGroupId != nil && *group.SecurityGroupId != "" {
			groupIDs = append(groupIDs, *group.SecurityGroupId)
		}
	}
	if len(groupIDs) == 0 {
		return nil
	}

	return ec2.DescribeSecurityGroupDetailsByFilters(ctx, ec2Client, []ec2Types.Filter{
		{
			Name:   stringPtr("group-id"),
			Values: groupIDs,
		},
	})
}

func describeClusterNetworkExposure(ctx context.Context, cacheClient *elasticache.Client, ec2Client *ec2Sdk.Client, cacheSubnetGroupName *string) ClusterNetworkExposure {
	exposure := ClusterNetworkExposure{}
	if cacheSubnetGroupName != nil {
		exposure.CacheSubnetGroupName = *cacheSubnetGroupName
	}
	if ec2Client == nil || cacheClient == nil || cacheSubnetGroupName == nil || *cacheSubnetGroupName == "" {
		return exposure
	}

	output, err := cacheClient.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{
		CacheSubnetGroupName: cacheSubnetGroupName,
	})
	if err != nil || output == nil || len(output.CacheSubnetGroups) == 0 {
		if err != nil {
			log.CtxLogger(ctx).Warn("describe cache subnet groups failed", zap.String("cacheSubnetGroup", *cacheSubnetGroupName), zap.Error(err))
		}
		return exposure
	}

	subnetGroup := output.CacheSubnetGroups[0]
	if subnetGroup.VpcId != nil {
		exposure.VpcID = *subnetGroup.VpcId
	}

	subnetIDs := make([]string, 0, len(subnetGroup.Subnets))
	for _, s := range subnetGroup.Subnets {
		if s.SubnetIdentifier != nil && *s.SubnetIdentifier != "" {
			subnetIDs = append(subnetIDs, *s.SubnetIdentifier)
		}
	}
	if len(subnetIDs) == 0 {
		return exposure
	}
	exposure.SubnetIDs = subnetIDs

	subnetOutput, err := ec2Client.DescribeSubnets(ctx, &ec2Sdk.DescribeSubnetsInput{SubnetIds: subnetIDs})
	if err != nil {
		log.CtxLogger(ctx).Warn("describe subnets failed", zap.String("cacheSubnetGroup", *cacheSubnetGroupName), zap.Error(err))
		return exposure
	}

	subnetVpcMap := map[string]string{}
	for _, subnet := range subnetOutput.Subnets {
		if subnet.SubnetId == nil || *subnet.SubnetId == "" {
			continue
		}
		subnetID := *subnet.SubnetId
		if subnet.VpcId != nil {
			subnetVpcMap[subnetID] = *subnet.VpcId
			if exposure.VpcID == "" {
				exposure.VpcID = *subnet.VpcId
			}
		}
		if subnet.MapPublicIpOnLaunch != nil && *subnet.MapPublicIpOnLaunch {
			exposure.HasPublicSubnet = true
		}
	}

	for _, subnetID := range subnetIDs {
		vpcID := subnetVpcMap[subnetID]
		igwRoute, eigwRoute := subnetHasInternetRoute(ctx, ec2Client, subnetID, vpcID)
		if igwRoute {
			exposure.HasInternetGatewayRoute = true
		}
		if eigwRoute {
			exposure.HasEgressOnlyGatewayIPv6 = true
		}
		if exposure.HasInternetGatewayRoute && exposure.HasEgressOnlyGatewayIPv6 {
			break
		}
	}

	return exposure
}

func subnetHasInternetRoute(ctx context.Context, ec2Client *ec2Sdk.Client, subnetID, vpcID string) (bool, bool) {
	routeTables := describeRouteTablesByFilters(ctx, ec2Client, []ec2Types.Filter{{
		Name:   stringPtr("association.subnet-id"),
		Values: []string{subnetID},
	}})
	if len(routeTables) == 0 && vpcID != "" {
		routeTables = describeRouteTablesByFilters(ctx, ec2Client, []ec2Types.Filter{
			{
				Name:   stringPtr("vpc-id"),
				Values: []string{vpcID},
			},
			{
				Name:   stringPtr("association.main"),
				Values: []string{"true"},
			},
		})
	}

	var hasIGW bool
	var hasEIGW bool
	for _, rt := range routeTables {
		for _, r := range rt.Routes {
			destinationIPv4 := r.DestinationCidrBlock != nil && *r.DestinationCidrBlock == "0.0.0.0/0"
			destinationIPv6 := r.DestinationIpv6CidrBlock != nil && *r.DestinationIpv6CidrBlock == "::/0"

			if destinationIPv4 && r.GatewayId != nil && strings.HasPrefix(*r.GatewayId, "igw-") {
				hasIGW = true
			}
			if destinationIPv6 && r.EgressOnlyInternetGatewayId != nil && strings.HasPrefix(*r.EgressOnlyInternetGatewayId, "eigw-") {
				hasEIGW = true
			}
		}
	}
	return hasIGW, hasEIGW
}

func describeRouteTablesByFilters(ctx context.Context, ec2Client *ec2Sdk.Client, filters []ec2Types.Filter) []ec2Types.RouteTable {
	input := &ec2Sdk.DescribeRouteTablesInput{Filters: filters}
	output, err := ec2Client.DescribeRouteTables(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("describe route tables failed", zap.Error(err))
		return nil
	}
	routeTables := append([]ec2Types.RouteTable{}, output.RouteTables...)
	for output.NextToken != nil {
		input.NextToken = output.NextToken
		output, err = ec2Client.DescribeRouteTables(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("describe route tables failed", zap.Error(err))
			return routeTables
		}
		routeTables = append(routeTables, output.RouteTables...)
	}
	return routeTables
}

func stringPtr(v string) *string {
	return &v
}

func describeCacheClusters(ctx context.Context, c *elasticache.Client) (cacheClusters []types.CacheCluster, err error) {
	input := &elasticache.DescribeCacheClustersInput{}
	output, err := c.DescribeCacheClusters(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeCacheClusters error", zap.Error(err))
		return nil, err
	}
	cacheClusters = append(cacheClusters, output.CacheClusters...)
	for output.Marker != nil {
		input.Marker = output.Marker
		output, err = c.DescribeCacheClusters(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("DescribeCacheClusters error", zap.Error(err))
			return nil, err
		}
		cacheClusters = append(cacheClusters, output.CacheClusters...)
	}

	return cacheClusters, nil
}
