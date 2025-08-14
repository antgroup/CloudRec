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

	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetMacieSessionResource returns AWS Macie session resource definition
func GetMacieSessionResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.MacieSession,
		ResourceTypeName:   "Macie Session",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/macie/latest/APIReference/macie.html",
		ResourceDetailFunc: GetMacieSessionDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Session.AccountId",
			ResourceName: "$.Session.Status",
		},
		Dimension: schema.Regional,
	}
}

// MacieSessionDetail aggregates all information for a Macie session.
type MacieSessionDetail struct {
	Session *macie2.GetMacieSessionOutput
	Tags    map[string]string
}

// GetMacieSessionDetail fetches the details for the Macie session in a region.
func GetMacieSessionDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Macie

	session, err := getMacieSession(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to get Macie session", zap.Error(err))
		return err
	}

	detail := describeMacieSessionDetail(ctx, client, session)
	if detail != nil {
		res <- detail
	}

	return nil
}

// getMacieSession retrieves the Macie session information.
func getMacieSession(ctx context.Context, c *macie2.Client) (*macie2.GetMacieSessionOutput, error) {
	input := &macie2.GetMacieSessionInput{}
	output, err := c.GetMacieSession(ctx, input)
	if err != nil {
		return nil, err
	}
	return output, nil
}

// describeMacieSessionDetail fetches all details for a Macie session.
func describeMacieSessionDetail(ctx context.Context, client *macie2.Client, session *macie2.GetMacieSessionOutput) *MacieSessionDetail {
	var tags map[string]string

	// Get tags - Macie session doesn't typically have direct tags,
	// but we can extract relevant information from the session itself
	tags = extractSessionTags(session)

	return &MacieSessionDetail{
		Session: session,
		Tags:    tags,
	}
}

// extractSessionTags extracts relevant information from a session as tags
func extractSessionTags(session *macie2.GetMacieSessionOutput) map[string]string {
	tags := make(map[string]string)

	// Extract some key information from the session as tags
	tags["Status"] = string(session.Status)
	tags["FindingPublishingFrequency"] = string(session.FindingPublishingFrequency)

	return tags
}