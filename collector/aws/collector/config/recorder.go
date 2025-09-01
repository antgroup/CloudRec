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

package config

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetRecorderResource returns a Recorder Resource
func GetRecorderResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Config,
		ResourceTypeName:   "Config Recorder",
		ResourceGroupType:  constant.CONFIG,
		Desc:               `https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeConfigurationRecorders.html`,
		ResourceDetailFunc: GetRecorderDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Recorder.Name",
			ResourceName: "$.Recorder.Name",
		},
		Dimension: schema.Regional,
	}
}

// RecorderDetail aggregates all information for a single Config recorder.
type RecorderDetail struct {
	Recorder        types.ConfigurationRecorder
	Status          *types.ConfigurationRecorderStatus
	DeliveryChannel *types.DeliveryChannel
}

// GetRecorderDetail fetches the details for all Config recorders in a region.
func GetRecorderDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Config

	recorders, err := describeConfigurationRecorders(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to describe config recorders", zap.Error(err))
		return err
	}

	for _, recorder := range recorders {
		status, err := describeConfigurationRecorderStatus(ctx, client, *recorder.Name)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe config recorder status", zap.String("recorderName", *recorder.Name), zap.Error(err))
			continue
		}
		deliveryChannel, err := describeDeliveryChannels(ctx, client, *recorder.Name)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe delivery channels", zap.String("recorderName", *recorder.Name), zap.Error(err))
			continue
		}

		res <- &RecorderDetail{
			Recorder:        recorder,
			Status:          status,
			DeliveryChannel: deliveryChannel,
		}
	}

	return nil
}

// describeConfigurationRecorders retrieves all Config recorders in a region.
func describeConfigurationRecorders(ctx context.Context, c *configservice.Client) ([]types.ConfigurationRecorder, error) {
	output, err := c.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, err
	}
	return output.ConfigurationRecorders, nil
}

// describeConfigurationRecorderStatus retrieves the status for a single recorder.
func describeConfigurationRecorderStatus(ctx context.Context, c *configservice.Client, recorderName string) (*types.ConfigurationRecorderStatus, error) {
	output, err := c.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{
		ConfigurationRecorderNames: []string{recorderName},
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to describe config recorder status", zap.String("recorderName", recorderName), zap.Error(err))
		return nil, err
	}
	if len(output.ConfigurationRecordersStatus) > 0 {
		return &output.ConfigurationRecordersStatus[0], nil
	}
	return nil, nil
}

// describeDeliveryChannels retrieves the delivery channel for a single recorder.
func describeDeliveryChannels(ctx context.Context, c *configservice.Client, recorderName string) (*types.DeliveryChannel, error) {
	output, err := c.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{
		DeliveryChannelNames: []string{recorderName},
	})
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to describe delivery channels", zap.String("recorderName", recorderName), zap.Error(err))
		return nil, err
	}
	if len(output.DeliveryChannels) > 0 {
		return &output.DeliveryChannels[0], nil
	}
	return nil, nil
}
