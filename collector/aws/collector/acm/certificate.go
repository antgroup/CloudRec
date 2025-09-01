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

package acm

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetCertificateResource returns a Certificate Resource
func GetCertificateResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Certificate,
		ResourceTypeName:   "Certificate",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html",
		ResourceDetailFunc: GetCertificateDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Certificate.CertificateArn",
			ResourceName: "$.Certificate.DomainName",
		},
		Dimension: schema.Regional,
	}
}

// CertificateDetail aggregates all information for a single ACM certificate.
type CertificateDetail struct {
	Certificate types.CertificateDetail
	Tags        []types.Tag
}

// GetCertificateDetail fetches the details for all ACM certificates.
func GetCertificateDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).ACM

	certificates, err := listCertificates(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list certificates", zap.Error(err))
		return err
	}

	for _, certificate := range certificates {

		certificateDetail, err := describeCertificate(ctx, client, certificate.CertificateArn)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe certificate", zap.String("certificate", *certificate.CertificateArn), zap.Error(err))
		}

		tags, err := listCertificateTags(ctx, client, certificate.CertificateArn)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to list certificate tags", zap.String("certificate", *certificate.CertificateArn), zap.Error(err))
		}

		res <- &CertificateDetail{
			Certificate: certificateDetail,
			Tags:        tags,
		}
	}

	return nil
}

// listCertificates retrieves all ACM certificates.
func listCertificates(ctx context.Context, c *acm.Client) ([]types.CertificateSummary, error) {
	var certificates []types.CertificateSummary
	paginator := acm.NewListCertificatesPaginator(c, &acm.ListCertificatesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, page.CertificateSummaryList...)
	}
	return certificates, nil
}

// describeCertificate retrieves detailed information for a certificate.
func describeCertificate(ctx context.Context, c *acm.Client, certificateArn *string) (types.CertificateDetail, error) {
	output, err := c.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
		CertificateArn: certificateArn,
	})
	if err != nil {
		return types.CertificateDetail{}, err
	}
	return *output.Certificate, nil
}

// listCertificateTags retrieves all tags for a certificate.
func listCertificateTags(ctx context.Context, c *acm.Client, certificateArn *string) ([]types.Tag, error) {
	output, err := c.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
		CertificateArn: certificateArn,
	})
	if err != nil {
		return nil, err
	}
	return output.Tags, nil
}
