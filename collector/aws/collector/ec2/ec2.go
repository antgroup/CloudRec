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
	"context"
	"github.com/core-sdk/log"
	"go.uber.org/zap"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
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

// GetInstanceDetail streams each EC2 instance detail as the
// DescribeInstances pagination yields it and its security group lookup
// completes — both the listing and the per-instance enrich push
// incrementally, avoiding the 30s consumer idle timeout in core-sdk
// schema/platform.go when a region has many instances.
func GetInstanceDetail(ctx context.Context, iService schema.ServiceInterface, res chan<- any) (err error) {
	client := iService.(*collector.Services).EC2

	input := &ec2.DescribeInstancesInput{}
	for {
		output, err := client.DescribeInstances(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("describeInstance failed", zap.Error(err))
			return err
		}
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				res <- InstanceDetail{
					Instance: instance,
					SecurityGroups: DescribeSecurityGroupDetailsByFilters(ctx, client, []types.Filter{
						{
							Name:   aws.String("group-id"),
							Values: getInstanceSecurityGroupIds(instance),
						},
					}),
				}
			}
		}
		if output.NextToken == nil {
			return nil
		}
		input.NextToken = output.NextToken
	}
}

func getInstanceSecurityGroupIds(instance types.Instance) (ids []string) {
	for _, sg := range instance.SecurityGroups {
		ids = append(ids, *sg.GroupId)
	}
	return ids
}
