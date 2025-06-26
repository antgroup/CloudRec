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

package route53

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	"github.com/aws/aws-sdk-go-v2/service/route53domains/types"
	"github.com/cloudrec/aws/collector"
	"go.uber.org/zap"
	"time"
)

// GetDomainResource returns a Domain Resource
func GetDomainResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Domain,
		ResourceTypeName:   collector.Domain,
		ResourceGroupType:  constant.NET,
		Desc:               `https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_ListDomains.html`,
		ResourceDetailFunc: GetTheDomainDetail,
		RowField: schema.RowField{
			ResourceId:   "$.DomainSummary.DomainName",
			ResourceName: "$.DomainSummary.DomainName",
			Address:      "",
		},
		Dimension: schema.Global,
	}
}

type TheDomainDetail struct {

	// The Domain summary information.
	DomainSummary types.DomainSummary

	// The Domain detail information
	DomainDetail DomainDetail
}

// DomainDetail basically is route53.GetDomainDetailOutput
// Reference: AWS SDK for GO v2, service/route53domains/api_op_GetDomainDetail.go:45
type DomainDetail struct {

	// Email address to contact to report incorrect contact information for a domain,
	// to report that the domain is being used to send spam, to report that someone is
	// cybersquatting on a domain name, or report some other type of abuse.
	AbuseContactEmail *string

	// Phone number for reporting abuse.
	AbuseContactPhone *string

	// Provides details about the domain administrative contact.
	AdminContact *types.ContactDetail

	// Specifies whether contact information is concealed from WHOIS queries. If the
	// value is true , WHOIS ("who is") queries return contact information either for
	// Amazon Registrar or for our registrar associate, Gandi. If the value is false ,
	// WHOIS queries return the information that you entered for the admin contact.
	AdminPrivacy *bool

	// Specifies whether the domain registration is set to renew automatically.
	AutoRenew *bool

	// Provides details about the domain billing contact.
	BillingContact *types.ContactDetail

	// Specifies whether contact information is concealed from WHOIS queries. If the
	// value is true , WHOIS ("who is") queries return contact information either for
	// Amazon Registrar or for our registrar associate, Gandi. If the value is false ,
	// WHOIS queries return the information that you entered for the billing contact.
	BillingPrivacy *bool

	// The date when the domain was created as found in the response to a WHOIS query.
	// The date and time is in Unix time format and Coordinated Universal time (UTC).
	CreationDate *time.Time

	// A complex type that contains information about the DNSSEC configuration.
	DnssecKeys []types.DnssecKey

	// The name of a domain.
	DomainName *string

	// The date when the registration for the domain is set to expire. The date and
	// time is in Unix time format and Coordinated Universal time (UTC).
	ExpirationDate *time.Time

	// The name servers of the domain.
	Nameservers []types.Nameserver

	// Provides details about the domain registrant.
	RegistrantContact *types.ContactDetail

	// Specifies whether contact information is concealed from WHOIS queries. If the
	// value is true , WHOIS ("who is") queries return contact information either for
	// Amazon Registrar or for our registrar associate, Gandi. If the value is false ,
	// WHOIS queries return the information that you entered for the registrant contact
	// (domain owner).
	RegistrantPrivacy *bool

	// Name of the registrar of the domain as identified in the registry.
	RegistrarName *string

	// Web address of the registrar.
	RegistrarUrl *string

	// Reserved for future use.
	RegistryDomainId *string

	// Reseller of the domain. Domains registered or transferred using Route 53
	// domains will have "Amazon" as the reseller.
	Reseller *string

	// An array of domain name status codes, also known as Extensible Provisioning
	// Protocol (EPP) status codes.
	//
	// ICANN, the organization that maintains a central database of domain names, has
	// developed a set of domain name status codes that tell you the status of a
	// variety of operations on a domain name, for example, registering a domain name,
	// transferring a domain name to another registrar, renewing the registration for a
	// domain name, and so on. All registrars use this same set of status codes.
	//
	// For a current list of domain name status codes and an explanation of what each
	// code means, go to the [ICANN website]and search for epp status codes . (Search on the ICANN
	// website; web searches sometimes return an old version of the document.)
	//
	// [ICANN website]: https://www.icann.org/
	StatusList []string

	// Provides details about the domain technical contact.
	TechContact *types.ContactDetail

	// Specifies whether contact information is concealed from WHOIS queries. If the
	// value is true , WHOIS ("who is") queries return contact information either for
	// Amazon Registrar or for our registrar associate, Gandi. If the value is false ,
	// WHOIS queries return the information that you entered for the technical contact.
	TechPrivacy *bool

	// The last updated date of the domain as found in the response to a WHOIS query.
	// The date and time is in Unix time format and Coordinated Universal time (UTC).
	UpdatedDate *time.Time

	// The fully qualified name of the WHOIS server that can answer the WHOIS query
	// for the domain.
	WhoIsServer *string
}

func GetTheDomainDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {

	client := service.(*collector.Services).Route53Domains

	domainDetails, err := describeDomainDetails(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Warn("describeDomainDetails error", zap.Error(err))
		return err
	}

	for _, domainDetail := range domainDetails {
		res <- domainDetail
	}

	return nil
}

func describeDomainDetails(ctx context.Context, c *route53domains.Client) (domainDetails []TheDomainDetail, err error) {
	domains, err := listDomains(ctx, c)
	if err != nil {
		log.CtxLogger(ctx).Warn("listDomains error", zap.Error(err))
		return nil, err
	}
	for _, domain := range domains {
		domainDetails = append(domainDetails, TheDomainDetail{
			DomainSummary: domain,
			DomainDetail:  getDomainDetail(ctx, c, domain),
		})
	}
	return domainDetails, nil
}

func listDomains(ctx context.Context, c *route53domains.Client) (domains []types.DomainSummary, err error) {

	input := &route53domains.ListDomainsInput{}
	output, err := c.ListDomains(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("listDomains error", zap.Error(err))
		return nil, err
	}
	domains = append(domains, output.Domains...)
	for output.NextPageMarker != nil {
		input.Marker = output.NextPageMarker
		output, err = c.ListDomains(ctx, input)
		if err != nil {
			log.CtxLogger(ctx).Warn("listDomains error", zap.Error(err))
			return nil, err
		}
		domains = append(domains, output.Domains...)
	}

	return domains, nil
}

func getDomainDetail(ctx context.Context, c *route53domains.Client, domain types.DomainSummary) DomainDetail {
	input := &route53domains.GetDomainDetailInput{DomainName: domain.DomainName}
	output, err := c.GetDomainDetail(ctx, input)
	if err != nil {
		log.CtxLogger(ctx).Warn("getDomainDetail error", zap.Error(err))
		return DomainDetail{}
	}
	return DomainDetail{
		AbuseContactEmail: output.AbuseContactEmail,
		AbuseContactPhone: output.AbuseContactPhone,
		AdminContact:      output.AdminContact,
		AdminPrivacy:      output.AdminPrivacy,
		AutoRenew:         output.AutoRenew,
		BillingContact:    output.BillingContact,
		BillingPrivacy:    output.BillingPrivacy,
		CreationDate:      output.CreationDate,
		DnssecKeys:        output.DnssecKeys,
		DomainName:        output.DomainName,
		ExpirationDate:    output.ExpirationDate,
		Nameservers:       output.Nameservers,
		RegistrantContact: output.RegistrantContact,
		RegistrantPrivacy: output.RegistrantPrivacy,
		RegistrarName:     output.RegistrarName,
		RegistrarUrl:      output.RegistrarUrl,
		RegistryDomainId:  output.RegistryDomainId,
		Reseller:          output.Reseller,
		StatusList:        output.StatusList,
		TechContact:       output.TechContact,
		TechPrivacy:       output.TechPrivacy,
		UpdatedDate:       output.UpdatedDate,
		WhoIsServer:       output.WhoIsServer,
	}

}
