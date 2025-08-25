// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package account

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetAccountResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Account,
		ResourceTypeName:   "Account",
		ResourceGroupType:  constant.SECURITY,
		Desc:               "https://docs.aws.amazon.com/accounts/latest/reference/API_GetContactInformation.html",
		ResourceDetailFunc: GetAccountDetail,
		RowField: schema.RowField{
			ResourceId:   "$.PrimaryContactInformation.FullName",
			ResourceName: "$.PrimaryContactInformation.FullName",
		},
		Dimension: schema.Global,
	}
}

type AccountDetail struct {
	PrimaryContactInformation *types.ContactInformation
	AlternateContacts         map[string]types.AlternateContact
}

func GetAccountDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).Account

	primaryContact, err := client.GetContactInformation(ctx, &account.GetContactInformationInput{})
	if err != nil {
		log.CtxLogger(ctx).Error("failed to get primary contact information", zap.Error(err))
		return err
	}

	alternateContacts := make(map[string]types.AlternateContact)
	contactTypes := []types.AlternateContactType{types.AlternateContactTypeBilling, types.AlternateContactTypeSecurity, types.AlternateContactTypeOperations}
	for _, contactType := range contactTypes {
		resp, err := client.GetAlternateContact(ctx, &account.GetAlternateContactInput{
			AlternateContactType: contactType,
		})
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to get alternate contact", zap.String("type", string(contactType)), zap.Error(err))
			continue
		}
		if resp.AlternateContact != nil {
			alternateContacts[string(contactType)] = *resp.AlternateContact
		}
	}

	res <- AccountDetail{
		PrimaryContactInformation: primaryContact.ContactInformation,
		AlternateContacts:         alternateContacts,
	}

	return nil
}
