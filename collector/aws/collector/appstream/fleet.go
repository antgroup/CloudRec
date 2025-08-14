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

package appstream

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	"github.com/aws/aws-sdk-go-v2/service/appstream/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"sync"
)

const maxWorkers = 10

func GetFleetResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.AppStreamFleet,
		ResourceTypeName:   "AppStream Fleet",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://docs.aws.amazon.com/appstream2/latest/APIReference/API_DescribeFleets.html",
		ResourceDetailFunc: GetFleetDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Fleet.Arn",
			ResourceName: "$.Fleet.Name",
		},
		Dimension: schema.Regional,
	}
}

type FleetDetail struct {
	Fleet types.Fleet
	Tags  map[string]string
}

func GetFleetDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).AppStream

	fleets, err := describeFleets(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe appstream fleets", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.Fleet, len(fleets))

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fleet := range tasks {
				res <- describeFleetDetail(ctx, client, fleet)
			}
		}()
	}

	for _, fleet := range fleets {
		tasks <- fleet
	}
	close(tasks)

	wg.Wait()
	return nil
}

func describeFleetDetail(ctx context.Context, client *appstream.Client, fleet types.Fleet) FleetDetail {
	tags, err := client.ListTagsForResource(ctx, &appstream.ListTagsForResourceInput{
		ResourceArn: fleet.Arn,
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for appstream fleet", zap.String("arn", *fleet.Arn), zap.Error(err))
	}

	return FleetDetail{
		Fleet: fleet,
		Tags:  tags.Tags,
	}
}

func describeFleets(ctx context.Context, c *appstream.Client) ([]types.Fleet, error) {
	var fleets []types.Fleet
	input := &appstream.DescribeFleetsInput{}
	for {
		output, err := c.DescribeFleets(ctx, input)
		if err != nil {
			return nil, err
		}
		fleets = append(fleets, output.Fleets...)
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}
	return fleets, nil
}
