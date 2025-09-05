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

package cloudtrail

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetTrailResource returns a Trail Resource
func GetTrailResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CloudTrail,
		ResourceTypeName:   "CloudTrail Trail",
		ResourceGroupType:  constant.CONFIG,
		Desc:               `https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html`,
		ResourceDetailFunc: GetTrailDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Trail.TrailARN",
			ResourceName: "$.Trail.Name",
		},
		Dimension: schema.Regional, // Trails can be regional or multi-regional, but we list them per region.
	}
}

// TrailDetail aggregates all information for a single CloudTrail trail.
type TrailDetail struct {
	Trail          types.Trail
	Status         *cloudtrail.GetTrailStatusOutput
	EventSelectors []types.EventSelector
	Tags           []types.Tag
}

// GetTrailDetail fetches the details for all CloudTrail trails in a region.
func GetTrailDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).CloudTrail

	trails, err := describeTrails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe cloudtrail trails", zap.Error(err))
		return err
	}

	for _, trail := range trails {
		status, err := getTrailStatus(ctx, client, trail.TrailARN)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to get trail status", zap.String("trailARN", *trail.TrailARN), zap.Error(err))
		}

		eventSelectors, err := getEventSelectors(ctx, client, trail.TrailARN)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to get event selectors", zap.String("trailARN", *trail.TrailARN), zap.Error(err))
		}

		tags, err := listTags(ctx, client, trail.TrailARN)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list tags", zap.String("trailARN", *trail.TrailARN), zap.Error(err))
		}

		res <- &TrailDetail{
			Trail:          trail,
			Status:         status,
			EventSelectors: eventSelectors,
			Tags:           tags,
		}
	}

	return nil
}

// describeTrails retrieves all CloudTrail trails in a region.
func describeTrails(ctx context.Context, c *cloudtrail.Client) ([]types.Trail, error) {
	output, err := c.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}
	return output.TrailList, nil
}

// getTrailStatus retrieves the status for a single trail.
func getTrailStatus(ctx context.Context, c *cloudtrail.Client, trailARN *string) (*cloudtrail.GetTrailStatusOutput, error) {
	output, err := c.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: trailARN})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get trail status", zap.String("trailARN", *trailARN), zap.Error(err))
		return nil, err
	}
	return output, nil
}

// getEventSelectors retrieves the event selectors for a single trail.
func getEventSelectors(ctx context.Context, c *cloudtrail.Client, trailARN *string) ([]types.EventSelector, error) {
	output, err := c.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: trailARN})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get event selectors", zap.String("trailARN", *trailARN), zap.Error(err))
		return nil, err
	}
	return output.EventSelectors, nil
}

// listTags retrieves all tags for a trail.
func listTags(ctx context.Context, c *cloudtrail.Client, trailARN *string) ([]types.Tag, error) {
	var tags []types.Tag
	paginator := cloudtrail.NewListTagsPaginator(c, &cloudtrail.ListTagsInput{ResourceIdList: []string{*trailARN}})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list cloudtrail tags", zap.String("trailARN", *trailARN), zap.Error(err))
			return nil, err
		}
		if len(page.ResourceTagList) > 0 {
			tags = append(tags, page.ResourceTagList[0].TagsList...)
		}
	}
	return tags, nil
}
