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

package sns

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetSNSTopicResource returns a SNS Topic Resource
func GetSNSTopicResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SNSTopic,
		ResourceTypeName:   "SNS Topic",
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               "https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html",
		ResourceDetailFunc: GetSNSTopicDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Topic.TopicArn",
			ResourceName: "$.Topic.TopicArn",
		},
		Dimension: schema.Regional,
	}
}

// SNSTopicDetail aggregates all information for a single SNS topic.
type SNSTopicDetail struct {
	Topic         types.Topic
	Attributes    map[string]string
	Policy        *map[string]interface{}
	Subscriptions []types.Subscription
	Tags          []types.Tag
}

// GetSNSTopicDetail fetches the details for all SNS topics.
func GetSNSTopicDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).SNS

	topics, err := listTopics(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list SNS topics", zap.Error(err))
		return err
	}

	for _, topic := range topics {
		detail := describeSNSTopicDetail(ctx, client, topic)
		res <- detail
	}

	return nil
}

// describeSNSTopicDetail fetches all details for a single SNS topic.
func describeSNSTopicDetail(ctx context.Context, client *sns.Client, topic types.Topic) *SNSTopicDetail {
	var attributes map[string]string
	var policy *map[string]interface{}
	var subscriptions []types.Subscription
	var tags []types.Tag

	attrs, err := getTopicAttributes(ctx, client, topic.TopicArn)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to get topic attributes", zap.String("topic", *topic.TopicArn), zap.Error(err))
	} else {
		attributes = attrs
		// Extract policy from attributes if available
		if policyStr, ok := attrs["Policy"]; ok {
			var policyObj map[string]interface{}
			err = json.Unmarshal([]byte(policyStr), &policyObj)
			if err == nil {
				policy = &policyObj
			}
		}
	}

	subs, err := listSubscriptionsByTopic(ctx, client, topic.TopicArn)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list subscriptions by topic", zap.String("topic", *topic.TopicArn), zap.Error(err))
	} else {
		subscriptions = subs
	}

	tagList, err := listTagsForResource(ctx, client, topic.TopicArn)
	if err != nil {
		log.CtxLogger(ctx).Warn("failed to list tags for topic", zap.String("topic", *topic.TopicArn), zap.Error(err))
	} else {
		tags = tagList
	}

	return &SNSTopicDetail{
		Topic:         topic,
		Attributes:    attributes,
		Policy:        policy,
		Subscriptions: subscriptions,
		Tags:          tags,
	}
}

// listTopics retrieves all SNS topics.
func listTopics(ctx context.Context, c *sns.Client) ([]types.Topic, error) {
	var topics []types.Topic
	paginator := sns.NewListTopicsPaginator(c, &sns.ListTopicsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		topics = append(topics, page.Topics...)
	}
	return topics, nil
}

// getTopicAttributes retrieves attributes for a topic.
func getTopicAttributes(ctx context.Context, c *sns.Client, topicArn *string) (map[string]string, error) {
	output, err := c.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
		TopicArn: topicArn,
	})
	if err != nil {
		return nil, err
	}
	return output.Attributes, nil
}

// listSubscriptionsByTopic retrieves all subscriptions for a topic.
func listSubscriptionsByTopic(ctx context.Context, c *sns.Client, topicArn *string) ([]types.Subscription, error) {
	var subscriptions []types.Subscription
	paginator := sns.NewListSubscriptionsByTopicPaginator(c, &sns.ListSubscriptionsByTopicInput{
		TopicArn: topicArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		subscriptions = append(subscriptions, page.Subscriptions...)
	}
	return subscriptions, nil
}

// listTagsForResource retrieves all tags for a topic.
func listTagsForResource(ctx context.Context, c *sns.Client, topicArn *string) ([]types.Tag, error) {
	output, err := c.ListTagsForResource(ctx, &sns.ListTagsForResourceInput{
		ResourceArn: topicArn,
	})
	if err != nil {
		return nil, err
	}
	return output.Tags, nil
}
