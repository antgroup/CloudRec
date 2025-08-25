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

package macie

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

const maxWorkers = 10

// GetClassificationJobResource returns AWS Macie classification job resource definition
func GetClassificationJobResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MacieJob,
		ResourceTypeName:   "Macie Classification Job",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/macie/latest/APIReference/jobs.html",
		ResourceDetailFunc: GetClassificationJobDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Job.JobId",
			ResourceName: "$.Job.Name",
		},
		Dimension: schema.Regional,
	}
}

// ClassificationJobDetail aggregates all information for a single Macie classification job.
type ClassificationJobDetail struct {
	Job  types.JobSummary
	Tags map[string]string
}

// GetClassificationJobDetail fetches the details for all Macie classification jobs in a region.
func GetClassificationJobDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Macie

	jobs, err := listClassificationJobs(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list Macie classification jobs", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	tasks := make(chan types.JobSummary, len(jobs))

	// Start worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range tasks {
				detail := describeClassificationJobDetail(ctx, client, job)
				if detail != nil {
					res <- detail
				}
			}
		}()
	}

	// Add tasks
	for _, job := range jobs {
		tasks <- job
	}
	close(tasks)

	wg.Wait()
	return nil
}

// listClassificationJobs retrieves all Macie classification jobs in a region.
func listClassificationJobs(ctx context.Context, c *macie2.Client) ([]types.JobSummary, error) {
	var jobs []types.JobSummary
	input := &macie2.ListClassificationJobsInput{
		MaxResults: aws.Int32(100),
	}

	paginator := macie2.NewListClassificationJobsPaginator(c, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, page.Items...)
	}
	return jobs, nil
}

// describeClassificationJobDetail fetches all details for a single classification job.
func describeClassificationJobDetail(ctx context.Context, client *macie2.Client, job types.JobSummary) *ClassificationJobDetail {
	var tags map[string]string

	// Copy the job to avoid race conditions
	jobCopy := job

	// Get tags - Macie jobs don't typically have direct tags,
	// but we can extract relevant information from the job itself
	tags = extractJobTags(&jobCopy)

	return &ClassificationJobDetail{
		Job:  jobCopy,
		Tags: tags,
	}
}

// extractJobTags extracts relevant information from a job as tags
func extractJobTags(job *types.JobSummary) map[string]string {
	tags := make(map[string]string)

	// Extract some key information from the job as tags
	if job.JobId != nil {
		tags["JobId"] = *job.JobId
	}
	
	if job.Name != nil {
		tags["Name"] = *job.Name
	}
	
	tags["Status"] = string(job.JobStatus)
	tags["Type"] = string(job.JobType)

	return tags
}