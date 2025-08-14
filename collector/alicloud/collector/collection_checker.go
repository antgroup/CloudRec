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

package collector

import (
	"context"
	"strings"
	"sync"
	"time"

	actiontrail20200706 "github.com/alibabacloud-go/actiontrail-20200706/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const (
	// Max number of events size
	maxEventSize = 20
	// Time format used for ActionTrail queries
	actionTrailTimeFormat = "2006-01-02T15:04:05Z"
	// Default query window for ActionTrail (7 days)
	defaultQueryDays = -7
	// ActionTrail API limitation (7 days)
	actionTrailMaxDays = -7
	// Connection timeout for ActionTrail client (10 seconds)
	actionTrailConnectTimeout = 10000
	// Read timeout for ActionTrail client (20 seconds)
	actionTrailReadTimeout = 20000
	// Error message for invalid access key
	invalidAccessKeyError = "InvalidAccessKeyId"
	// ActionTrail event type for write operations
	writeEventType = "Write"
	// ActionTrail lookup attribute key for event read/write type
	eventRWKey = "EventRW"
)

// getActionTrailRegions returns the list of regions to query for ActionTrail events
// Currently only queries cn-hangzhou region for performance optimization
// https://next.api.aliyun.com/product/Actiontrail
var actionTrailRegions = []string{
	"cn-hangzhou",
	"cn-qingdao", "cn-beijing", "cn-zhangjiakou", "cn-huhehaote",
	"cn-wulanchabu", "cn-shanghai", "cn-nanjing", "cn-shenzhen",
	"cn-heyuan", "cn-guangzhou", "ap-northeast-2", "ap-southeast-3",
	"ap-northeast-1", "ap-southeast-7", "cn-chengdu", "ap-southeast-1",
	"ap-southeast-5", "cn-hongkong", "eu-central-1", "us-east-1",
	"us-west-1", "na-south-1", "eu-west-1", "me-east-1", "cn-shanghai-finance-1",
}

// AssessCollectionTrigger determines whether asset collection should be performed for the cloud account
// It checks for write operations in ActionTrail within a specific time window to optimize collection frequency
// Returns CollectRecordInfo containing collection decision and metadata
func (s *Services) AssessCollectionTrigger(cloudAccountParam schema.CloudAccountParam) schema.CollectRecordInfo {
	// Initialize query time range (default: last 7 days to now)
	queryStartTime := cloudAccountParam.CollectRecordInfo.EndTime
	if queryStartTime == "" {
		queryStartTime = time.Now().UTC().AddDate(0, 0, defaultQueryDays).Format(actionTrailTimeFormat)
	}
	queryEndTime := time.Now().UTC().Format(actionTrailTimeFormat)

	// Initialize collection record info with default values
	recordInfo := schema.CollectRecordInfo{
		CloudAccountId:   cloudAccountParam.CloudAccountId,
		Platform:         cloudAccountParam.Platform,
		StartTime:        queryStartTime,
		EndTime:          queryEndTime,
		EnableCollection: true,
	}

	ctx := context.Background()
	cloudAccountId := cloudAccountParam.CloudAccountId

	// Skip ActionTrail check for first-time collection
	if cloudAccountParam.CollectRecordInfo.EndTime == "" {
		recordInfo.Message = "First time collection, skipping ActionTrail check"
		log.CtxLogger(ctx).Info(recordInfo.Message,
			zap.String("cloudAccountId", cloudAccountId))
		return recordInfo
	}

	// Parse and validate the last collection end time
	lastCollectEndTime, err := time.Parse(actionTrailTimeFormat, cloudAccountParam.CollectRecordInfo.EndTime)
	if err != nil {
		log.CtxLogger(ctx).Error("Invalid last collect end time format",
			zap.String("cloudAccountId", cloudAccountId),
			zap.Error(err))
		recordInfo.ErrorMessage = err.Error()
		return recordInfo
	}

	// Skip ActionTrail check if last collection was more than 7 days ago (API limitation)
	actionTrailCutoff := time.Now().UTC().AddDate(0, 0, actionTrailMaxDays)
	if lastCollectEndTime.Before(actionTrailCutoff) {
		recordInfo.Message = "Last collection was within 7 days, skipping ActionTrail check"
		log.CtxLogger(ctx).Info(recordInfo.Message,
			zap.String("cloudAccountId", cloudAccountId),
			zap.Time("lastCollectEndTime", lastCollectEndTime))
		return recordInfo
	}

	// Configure ActionTrail client
	commonParam := cloudAccountParam.CommonCloudAccountParam
	config := openapiConfig(commonParam.Region, commonParam.AK, commonParam.SK)
	config.ConnectTimeout = tea.Int(actionTrailConnectTimeout)
	config.ReadTimeout = tea.Int(actionTrailReadTimeout)

	// Set proxy configuration if provided
	if cloudAccountParam.ProxyConfig != "" {
		config.HttpProxy = tea.String(cloudAccountParam.ProxyConfig)
		config.HttpsProxy = tea.String(cloudAccountParam.ProxyConfig)
	}

	// Create ActionTrail lookup request for write operations
	writeEventAttribute := &actiontrail20200706.LookupEventsRequestLookupAttribute{
		Key:   tea.String(eventRWKey),
		Value: tea.String(writeEventType),
	}
	lookupEventsRequest := &actiontrail20200706.LookupEventsRequest{
		LookupAttribute: []*actiontrail20200706.LookupEventsRequestLookupAttribute{writeEventAttribute},
		StartTime:       tea.String(queryStartTime),
		EndTime:         tea.String(queryEndTime),
	}

	// Query ActionTrail across multiple regions for write operations using concurrent goroutines
	type regionResult struct {
		region       string
		events       int
		eventDetails []map[string]interface{}
		err          error
		isInvalidKey bool
	}

	resultChan := make(chan regionResult, len(actionTrailRegions))
	var wg sync.WaitGroup

	// Launch concurrent queries for each region
	for _, region := range actionTrailRegions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()

			// Create ActionTrail client for the region
			client, err := createActiontrailClient(region, config)
			if err != nil {
				log.CtxLogger(ctx).Warn("Failed to initialize ActionTrail client",
					zap.String("cloudAccountId", cloudAccountId),
					zap.String("region", region),
					zap.Error(err))
				resultChan <- regionResult{region: region, err: err}
				return
			}

			// Query for write events in the region
			response, err := client.LookupEvents(lookupEventsRequest)
			if err != nil {
				log.CtxLogger(ctx).Warn("Failed to lookup ActionTrail events",
					zap.String("cloudAccountId", cloudAccountId),
					zap.String("region", region),
					zap.Error(err))

				// Check if access key is invalid
				isInvalidKey := strings.Contains(err.Error(), invalidAccessKeyError)
				resultChan <- regionResult{region: region, err: err, isInvalidKey: isInvalidKey}
				return
			}

			// Send result with event count and event details
			eventCount := len(response.Body.Events)
			var eventDetails []map[string]interface{}
			for _, event := range response.Body.Events {
				eventDetails = append(eventDetails, event)
			}
			resultChan <- regionResult{region: region, events: eventCount, eventDetails: eventDetails}
		}(region)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results from all regions
	var lastError error
	var hasWriteOperations bool
	for result := range resultChan {
		if result.err != nil {
			// Stop collection immediately if access key is invalid
			if result.isInvalidKey {
				log.CtxLogger(ctx).Warn("Invalid AccessKey detected, stopping collection",
					zap.String("cloudAccountId", cloudAccountId),
					zap.String("region", result.region),
					zap.Error(result.err))
				recordInfo.EnableCollection = false
				recordInfo.ErrorMessage = result.err.Error()
				return recordInfo
			}
			lastError = result.err
			continue
		}

		// Collect event details from all regions
		recordInfo.Events = append(recordInfo.Events, result.eventDetails...)

		// Check if write operations found in this region
		if result.events > 0 {
			hasWriteOperations = true
			log.CtxLogger(ctx).Info("Write operations found in region",
				zap.String("cloudAccountId", cloudAccountId),
				zap.String("region", result.region),
				zap.Int("eventCount", result.events))
		}
	}

	// Determine final collection decision based on all regions
	if hasWriteOperations {
		recordInfo.Message = "Write operations found since last collection, proceeding with collection"
		log.CtxLogger(ctx).Info(recordInfo.Message,
			zap.String("cloudAccountId", cloudAccountId),
			zap.String("startTime", queryStartTime),
			zap.String("endTime", queryEndTime),
			zap.Bool("enableCollection", recordInfo.EnableCollection),
			zap.Int("totalEvents", len(recordInfo.Events)))
		return recordInfo
	}

	// Set error message if there were any errors during processing
	if lastError != nil {
		recordInfo.ErrorMessage = lastError.Error()
	}

	// No write operations found in any region, skip collection
	recordInfo.EnableCollection = false
	recordInfo.Message = "No write operations found since last collection, skipping collection"
	log.CtxLogger(ctx).Info(recordInfo.Message,
		zap.String("cloudAccountId", cloudAccountId),
		zap.String("startTime", queryStartTime),
		zap.String("endTime", queryEndTime),
		zap.Bool("enableCollection", recordInfo.EnableCollection))

	if len(recordInfo.Events) > maxEventSize {
		recordInfo.Events = recordInfo.Events[:maxEventSize]
	}
	return recordInfo
}
