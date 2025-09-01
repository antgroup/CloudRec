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

package rds

import (
	"context"
	"go.uber.org/zap"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Type "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	rdsType "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
)

// GetRDSInstanceResource returns a RDS instance Resource
func GetRDSInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.RDS,
		ResourceTypeName:   "RDS Instance",
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DBInstance.DbiResourceId",
			ResourceName: "$.DBInstance.DBInstanceIdentifier",
			Address:      "",
		},
		Dimension: schema.Regional,
	}
}

type InstanceDetail struct {

	// The DBInstance.
	DBInstance rdsType.DBInstance

	// A list of DBSecurityGroup instances.
	DBSecurityGroups []rdsType.DBSecurityGroup

	// A list if VPCSecurityGroup instances.
	VPCSecurityGroups []ec2Type.SecurityGroup
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	services := service.(*collector.Services)
	rdsClient := services.RDS
	ec2Client := services.EC2

	instanceDetails, err := describeInstanceDetails(ctx, rdsClient, ec2Client)
	if err != nil {
		return err
	}

	for _, instanceDetail := range instanceDetails {
		res <- instanceDetail
	}
	return nil
}

func describeInstanceDetails(ctx context.Context, rdsClient *rds.Client, ec2Client *ec2.Client) (instanceDetails []InstanceDetail, err error) {

	instances, err := describeInstances(ctx, rdsClient)
	if err != nil {
		return nil, err
	}
	for _, instance := range instances {
		instanceDetails = append(instanceDetails, InstanceDetail{
			DBInstance:        instance,
			DBSecurityGroups:  describeDBSecurityGroups(ctx, rdsClient, instance.DBSecurityGroups),
			VPCSecurityGroups: describeVPCSecurityGroups(ctx, ec2Client, instance.VpcSecurityGroups),
		})
	}

	return instanceDetails, nil
}

func describeVPCSecurityGroups(ctx context.Context, ec2Client *ec2.Client, groups []rdsType.VpcSecurityGroupMembership) (vpcSecurityGroups []ec2Type.SecurityGroup) {
	if groups == nil {
		return nil
	}
	for _, group := range groups {
		//if sg status is not active, continue
		if *group.Status != "active" {
			continue
		}
		input := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []string{*group.VpcSecurityGroupId},
		}
		output, err := ec2Client.DescribeSecurityGroups(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("describe security group failed", zap.Error(err))
			continue
		}
		vpcSecurityGroups = append(vpcSecurityGroups, output.SecurityGroups...)
	}
	return vpcSecurityGroups
}

// Obtain database security group information by using the RDS API
func describeDBSecurityGroups(ctx context.Context, c *rds.Client, groups []types.DBSecurityGroupMembership) (dBSecurityGroups []types.DBSecurityGroup) {
	if groups == nil {
		return nil
	}
	for _, group := range groups {
		input := &rds.DescribeDBSecurityGroupsInput{
			DBSecurityGroupName: group.DBSecurityGroupName,
		}
		output, err := c.DescribeDBSecurityGroups(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("describe rds security group failed", zap.Error(err))
			break
		}
		dBSecurityGroups = append(dBSecurityGroups, output.DBSecurityGroups...)
		for output.Marker != nil {
			input.Marker = output.Marker
			output, err = c.DescribeDBSecurityGroups(ctx, input)
			if err != nil {
				log.CtxLogger(ctx).Warn("describe rds security group failed", zap.Error(err))
				break
			}
			dBSecurityGroups = append(dBSecurityGroups, output.DBSecurityGroups...)
		}
	}
	return dBSecurityGroups
}

// Obtain the database instance information
func describeInstances(ctx context.Context, c *rds.Client) (instances []types.DBInstance, err error) {
	input := &rds.DescribeDBInstancesInput{}
	output, err := c.DescribeDBInstances(ctx, input)
	if err != nil {
		return nil, err
	}
	instances = append(instances, output.DBInstances...)
	for output.Marker != nil {
		input.Marker = output.Marker
		output, err = c.DescribeDBInstances(ctx, input)
		if err != nil {
			return nil, err
		}
		instances = append(instances, output.DBInstances...)
	}

	return instances, nil
}
