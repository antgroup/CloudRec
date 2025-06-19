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

package workspace

//import (
//	"github.com/core-sdk/constant"
//	"github.com/core-sdk/schema"
//	"context"
//	"github.com/cloudrec/gcp/collector"
//	admin "google.golang.org/api/admin/directory/v1"
//)
//
//func GetUserResource() schema.Resource {
//	return schema.Resource{
//		ResourceType:      collector.GoogleUser,
//		ResourceTypeName:  collector.GoogleUser,
//		ResourceGroupType: constant.IDENTITY,
//		Desc:              ``,
//		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
//			svc := service.(*collector.Services).Admin
//
//			if err := svc.Users.List().Pages(ctx, func(resp *admin.Users) error {
//				for _, user := range resp.Users {
//					res <- UserDetail{
//						User: user,
//					}
//				}
//				return nil
//			},
//			); err != nil {
//				return err
//			}
//
//			return nil
//		},
//		RowField: schema.RowField{
//			ResourceId:   "$.",
//			ResourceName: "$.",
//		},
//		Dimension: schema.Global,
//	}
//}
//
//type UserDetail struct {
//	User *admin.User
//}
