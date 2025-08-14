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

package guardduty

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"sync"
)

const (
	maxWorkers = 10
)

// GetDetectorResource returns a Detector Resource
func GetDetectorResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.GuardDuty,
		ResourceTypeName:   "GuardDuty Detector",
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html`,
		ResourceDetailFunc: GetDetectorDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Detector.DetectorId",
			ResourceName: "$.Detector.DetectorId", // No friendly name
		},
		Dimension: schema.Regional,
	}
}

// DetectorDetail aggregates all information for a single GuardDuty detector.
type DetectorDetail struct {
	Detector      *guardduty.GetDetectorOutput
	Administrator *types.Administrator
	Tags          map[string]string
}

// GetDetectorDetail fetches the details for all GuardDuty detectors in a region.
func GetDetectorDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).GuardDuty
	detectorIds, err := listDetectors(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list guardduty detectors", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan string, len(detectorIds))

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range tasks {
				detail := describeDetectorDetail(ctx, client, id)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks to the queue
	for _, detectorId := range detectorIds {
		tasks <- detectorId
	}
	close(tasks)

	wg.Wait()

	return nil
}

// describeDetectorDetail fetches all details for a single detector.
func describeDetectorDetail(ctx context.Context, client *guardduty.Client, detectorId string) *DetectorDetail {
	detector, err := getDetector(ctx, client, detectorId)
	if err != nil {
		return nil // If we can't get the detector, we can't proceed.
	}

	var wg sync.WaitGroup
	var administrator *types.Administrator
	var tags map[string]string

	wg.Add(2)

	go func() {
		defer wg.Done()
		administrator, _ = getAdministratorAccount(ctx, client, detectorId)
	}()

	go func() {
		defer wg.Done()
		arn := fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/%s", client.Options().Region, log.GetCloudAccountId(ctx), detectorId)
		tags, _ = listTagsForResource(ctx, client, arn)
	}()

	wg.Wait()

	return &DetectorDetail{
		Detector:      detector,
		Administrator: administrator,
		Tags:          tags,
	}
}

// listDetectors retrieves all GuardDuty detector IDs in a region.
func listDetectors(ctx context.Context, c *guardduty.Client) ([]string, error) {
	var detectorIds []string
	paginator := guardduty.NewListDetectorsPaginator(c, &guardduty.ListDetectorsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		detectorIds = append(detectorIds, page.DetectorIds...)
	}
	return detectorIds, nil
}

// getDetector retrieves the details for a single detector.
func getDetector(ctx context.Context, c *guardduty.Client, detectorId string) (*guardduty.GetDetectorOutput, error) {
	output, err := c.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: &detectorId})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get detector", zap.String("detectorId", detectorId), zap.Error(err))
		return nil, err
	}
	return output, nil
}

// getAdministratorAccount retrieves the administrator account for a detector.
func getAdministratorAccount(ctx context.Context, c *guardduty.Client, detectorId string) (*types.Administrator, error) {
	output, err := c.GetAdministratorAccount(ctx, &guardduty.GetAdministratorAccountInput{DetectorId: &detectorId})
	if err != nil {
		// This call fails if the account is not a member, which is a normal case.
		log.CtxLogger(ctx).Debug("failed to get administrator account", zap.String("detectorId", detectorId), zap.Error(err))
		return nil, err
	}
	return output.Administrator, nil
}

// listTagsForResource retrieves all tags for a resource.
func listTagsForResource(ctx context.Context, c *guardduty.Client, resourceArn string) (map[string]string, error) {
	output, err := c.ListTagsForResource(ctx, &guardduty.ListTagsForResourceInput{ResourceArn: &resourceArn})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for resource", zap.String("arn", resourceArn), zap.Error(err))
		return nil, err
	}
	return output.Tags, nil
}
