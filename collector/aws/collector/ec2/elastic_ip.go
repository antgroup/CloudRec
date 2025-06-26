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
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cloudrec/aws/collector"
)

// GetElasticIPResource returns a Elastic IP Resource
func GetElasticIPResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ElasticIP,
		ResourceTypeName:   "Elastic IP",
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAddresses.html`,
		ResourceDetailFunc: GetElasticIPDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Address.InstanceId",
			ResourceName: "$.Address.PublicIp",
			Address:      "$.Address.PublicIp",
		},
		Dimension: schema.Regional,
	}
}

type ElasticIPDetail struct {
	Address types.Address
}

func GetElasticIPDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EC2

	elasticIPDetails, err := describeElasticIPDetails(ctx, client)
	if err != nil {
		return err
	}

	for _, elasticIPDetail := range elasticIPDetails {
		res <- elasticIPDetail
	}

	return nil
}

func describeElasticIPDetails(ctx context.Context, c *ec2.Client) (elasticIPDetails []ElasticIPDetail, err error) {

	elasticIPAddresses, err := describeAddresses(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, elasticIPAddress := range elasticIPAddresses {
		elasticIPDetails = append(elasticIPDetails, ElasticIPDetail{
			Address: elasticIPAddress,
		})
	}

	return elasticIPDetails, nil
}

func describeAddresses(ctx context.Context, c *ec2.Client) (addresses []types.Address, err error) {
	input := &ec2.DescribeAddressesInput{}
	output, err := c.DescribeAddresses(ctx, input)
	if err != nil {
		return nil, err
	}
	addresses = append(addresses, output.Addresses...)

	return addresses, nil
}
