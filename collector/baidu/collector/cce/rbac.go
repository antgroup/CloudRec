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

package cce

import (
	"context"
	"github.com/baidubce/bce-sdk-go/services/iam"
	"go.uber.org/zap"

	"github.com/cloudrec/baidu/collector"
	"github.com/cloudrec/baidu/customsdk/cce"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
)

type RBACDetail struct {
	RBAC *cce.RBAC
}

func GetRBACResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.CCERBAC,
		ResourceTypeName:   collector.CCERBAC,
		ResourceGroupType:  constant.CONTAINER,
		Desc:               `https://cloud.baidu.com/doc/CCE/s/nkwopebgf`,
		ResourceDetailFunc: GetRBACDetail,
		RowField: schema.RowField{
			ResourceId:   "$.RBAC.clusterID",
			ResourceName: "$.RBAC.clusterName",
		},
		Regions: []string{
			"cce.bj.baidubce.com",
			"cce.gz.baidubce.com",
			"cce.su.baidubce.com",
			"cce.bd.baidubce.com",
			"cce.fwh.baidubce.com",
			"cce.hkg.baidubce.com",
			"cce.yq.baidubce.com",
			"cce.cd.baidubce.com",
			"cce.nj.baidubce.com",
		},
		Dimension: schema.Regional,
	}
}
func GetRBACDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	rbacClient := service.(*collector.Services).CCECustomClient
	accessKeyId := rbacClient.BceClient.Config.Credentials.AccessKeyId
	secretAccessKey := rbacClient.BceClient.Config.Credentials.SecretAccessKey
	iamClient, err := iam.NewClient(accessKeyId, secretAccessKey)
	log.GetWLogger().Info("cce rbac", zap.String("accessKeyId", accessKeyId))
	if err != nil {
		log.GetWLogger().Warn("init iam client failed", zap.Error(err))
		return err
	}
	users, err := iamClient.ListUser()
	if err != nil {
		log.CtxLogger(ctx).Error("iamClient ListUser error", zap.Error(err))

		return err
	}
	for _, user := range users.Users {
		arg := &cce.ListRBACsRequest{
			UserID: user.Id,
		}
		rbacResponse, tmpErr := rbacClient.ListRBACs(arg)
		if tmpErr != nil || rbacResponse == nil {
			log.CtxLogger(ctx).Warn("rbacClient ListRBACs error", zap.Error(tmpErr))
			continue
		}
		log.GetWLogger().Info("cce rbac", zap.String("user.Name", user.Name), zap.String("user.ID", user.Id), zap.Int("len", len(rbacResponse.Data)))
		for _, rbacDetail := range rbacResponse.Data {
			detail := RBACDetail{
				RBAC: rbacDetail,
			}
			res <- detail
		}
	}

	return nil
}
