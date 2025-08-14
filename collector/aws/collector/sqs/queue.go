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

package sqs

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"strings"
	"sync"
)

const maxWorkers = 10

// GetSQSQueueResource returns a SQS Queue Resource
func GetSQSQueueResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.SQSQueue,
		ResourceTypeName:   "SQS Queue",
		ResourceGroupType:  constant.MIDDLEWARE,
		Desc:               "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListQueues.html",
		ResourceDetailFunc: GetSQSQueueDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Queue.QueueUrl",
			ResourceName: "$.Queue.Name",
		},
		Dimension: schema.Regional,
	}
}

// SQSQueueDetail aggregates all information for a single SQS queue.
type SQSQueueDetail struct {
	Url        string
	Name       string
	Region     string
	Attributes map[string]string
	Policy     *map[string]interface{}
	Tags       map[string]string
}

// GetSQSQueueDetail fetches the details for all SQS queues.
func GetSQSQueueDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).SQS

	queues, err := listQueues(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list SQS queues", zap.Error(err))
		return err
	}

	jobs := make(chan SQSQueueDetail, len(queues))
	var wg sync.WaitGroup
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for queue := range jobs {
				detail := describeSQSQueueDetail(ctx, client, queue)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}
	for _, queue := range queues {
		jobs <- queue
	}
	close(jobs)
	wg.Wait()

	return nil
}

// describeSQSQueueDetail fetches all details for a single SQS queue.
func describeSQSQueueDetail(ctx context.Context, client *sqs.Client, queue SQSQueueDetail) *SQSQueueDetail {
	var wg sync.WaitGroup
	var attributes map[string]string
	var policy *map[string]interface{}
	var tags map[string]string

	wg.Add(2)

	go func() {
		defer wg.Done()
		attrs, err := getQueueAttributes(ctx, client, queue.Url)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to get queue attributes", zap.String("queue", queue.Url), zap.Error(err))
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
	}()

	go func() {
		defer wg.Done()
		tagMap, err := listQueueTags(ctx, client, queue.Url)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list tags for queue", zap.String("queue", queue.Url), zap.Error(err))
		} else {
			tags = tagMap
		}
	}()

	wg.Wait()

	queue.Attributes = attributes
	queue.Policy = policy
	queue.Tags = tags

	return &queue
}

// listQueues retrieves all SQS queues.
func listQueues(ctx context.Context, c *sqs.Client) ([]SQSQueueDetail, error) {
	var queues []SQSQueueDetail

	// Get the region from the client
	region := c.Options().Region

	maxResults := int32(1000)
	input := &sqs.ListQueuesInput{
		MaxResults: &maxResults,
	}

	paginator := sqs.NewListQueuesPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, queueUrl := range page.QueueUrls {
			// Extract queue name from URL
			queueName := queueUrl
			if len(queueUrl) > 0 {
				parts := strings.Split(queueUrl, "/")
				if len(parts) > 0 {
					queueName = parts[len(parts)-1]
				}
			}

			queues = append(queues, SQSQueueDetail{
				Url:    queueUrl,
				Name:   queueName,
				Region: region,
			})
		}
	}

	return queues, nil
}

// getQueueAttributes retrieves attributes for a queue.
func getQueueAttributes(ctx context.Context, c *sqs.Client, queueUrl string) (map[string]string, error) {
	output, err := c.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       &queueUrl,
		AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameAll},
	})
	if err != nil {
		return nil, err
	}
	return output.Attributes, nil
}

// listQueueTags retrieves all tags for a queue.
func listQueueTags(ctx context.Context, c *sqs.Client, queueUrl string) (map[string]string, error) {
	output, err := c.ListQueueTags(ctx, &sqs.ListQueueTagsInput{
		QueueUrl: &queueUrl,
	})
	if err != nil {
		return nil, err
	}
	return output.Tags, nil
}
