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

package ec2

import (
	"github.com/core-sdk/log"
	"context"
	"go.uber.org/zap"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
)

// GetInstanceResource returns a schema.Resource type struct which defines a type of resource.
func GetInstanceResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EC2,
		ResourceTypeName:   "EC2 Instance",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               `https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html`,
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
			Address:      "$.Instance.PublicIpAddress",
		},
		Dimension: schema.Regional,
	}
}

// InstanceDetail Describes an instance, and includes security group information that applies to the instance
type InstanceDetail struct {

	// The EC2 instances.
	Instance types.Instance

	// The security groups that apply to the instance
	SecurityGroups []SecurityGroupDetail

	// to be expanded
	// any information about EC2 instance
}

// GetInstanceDetail gets all InstanceDetail struct instances and sends them to a channel received by server finally, returns error
func GetInstanceDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) (err error) {
	// 1. get client
	client := iService.(*collector.Services).EC2

	// 2. invoke api of sdk to describe InstanceDetail struct instances
	instanceDetails, err := describeInstanceDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeInstanceDetails failed, err", zap.Error(err))
		return err
	}

	// 3. send instances to channel
	for _, instanceDetail := range instanceDetails {
		res <- instanceDetail
	}

	return nil
}

func describeInstanceDetails(ctx context.Context, client *ec2.Client) (instanceDetails []InstanceDetail, err error) {
	instances, err := describeInstance(ctx, client)

	for _, instance := range instances {
		instanceDetails = append(instanceDetails, InstanceDetail{
			Instance: instance,
			SecurityGroups: DescribeSecurityGroupDetailsByFilters(ctx, client, []types.Filter{
				{
					Name:   aws.String("group-id"),
					Values: getInstanceSecurityGroupIds(instance),
				},
			}),
		})
	}

	return instanceDetails, nil
}

func describeInstance(ctx context.Context, client *ec2.Client) (instances []types.Instance, err error) {
	input := &ec2.DescribeInstancesInput{
		NextToken: nil,
	}
	output, err := client.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}
	for _, reservation := range output.Reservations {
		instances = append(instances, reservation.Instances...)
	}
	for output.NextToken != nil {
		input = &ec2.DescribeInstancesInput{
			NextToken: output.NextToken,
		}
		output, err = client.DescribeInstances(ctx, input)
		for _, reservation := range output.Reservations {
			instances = append(instances, reservation.Instances...)
		}
	}

	return instances, err
}

func getInstanceSecurityGroupIds(instance types.Instance) (ids []string) {
	for _, sg := range instance.SecurityGroups {
		ids = append(ids, *sg.GroupId)
	}
	return ids
}
