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

package redis

import (
	"context"
	"github.com/baidubce/bce-sdk-go/services/scs"
	"github.com/cloudrec/baidu/collector"
	"github.com/cloudrec/baidu/customsdk/redis"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

type Detail struct {
	Instance       scs.InstanceModel
	SecurityGroups []scs.SecurityGroupDetail
	SecurityIps    []string
	Accounts       []*redis.Account
	// SecurityGroupRules *redis.ListSecurityGroupsResponse
}

func GetResource() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.Redis,
		ResourceTypeName:  collector.Redis,
		ResourceGroupType: constant.STORE,
		Desc:              `https://cloud.baidu.com/doc/SCS/s/Ykhej7sv2`,
		Regions: []string{
			"redis.bj.baidubce.com",
			"redis.bd.baidubce.com",
			"redis.gz.baidubce.com",
			"redis.su.baidubce.com",
			"redis.fwh.baidubce.com",
			"redis.hkg.baidubce.com",
		},
		ResourceDetailFunc: GetInstanceDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.instanceId",
			ResourceName: "$.Instance.instanceName",
		},
		Dimension: schema.Regional,
	}
}

func GetInstanceDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).RedisClient
	accessKeyId := client.BceClient.Config.Credentials.AccessKeyId
	secretAccessKey := client.BceClient.Config.Credentials.SecretAccessKey
	redisAccountClient, err := redis.NewClient(accessKeyId, secretAccessKey, client.Config.Endpoint)
	if err != nil {
		log.GetWLogger().Warn("init redisAccountClient failed", zap.Error(err))
	}

	arg := &scs.ListInstancesArgs{
		MaxKeys: 10,
		Marker:  "",
	}
	for {
		response, err := client.ListInstances(arg)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListInstances error", zap.Error(err))
			return err
		}
		for _, i := range response.Instances {

			d := Detail{
				Instance:       i,
				SecurityGroups: listSecurityGroupByInstanceId(ctx, client, i.InstanceID),
				SecurityIps:    GetSecurityIp(ctx, client, i.InstanceID),
				Accounts:       GetAccounts(ctx, redisAccountClient, i.InstanceID),
				// SecurityGroupRules: GetSecurityGroupRules(ctx, redisAccountClient, i.InstanceID),
			}
			res <- d
		}
		if response.NextMarker == "" {
			break
		}
		arg.Marker = response.NextMarker
	}
	return nil
}

func listSecurityGroupByInstanceId(ctx context.Context, client *scs.Client, instanceId string) []scs.SecurityGroupDetail {
	resp, err := client.ListSecurityGroupByInstanceId(instanceId)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListSecurityGroupByInstanceId error", zap.Error(err))
		return nil
	}

	return resp.Groups
}

func GetSecurityIp(ctx context.Context, client *scs.Client, instanceId string) []string {
	resp, err := client.GetSecurityIp(instanceId)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetSecurityIps error", zap.Error(err))
		return nil
	}
	return resp.SecurityIps
}

func GetAccounts(ctx context.Context, client *redis.Client, instanceId string) []*redis.Account {
	if client == nil {
		log.CtxLogger(ctx).Warn("redis AccountClient is nil")
		return nil
	}
	arg := &redis.ListAccountsRequest{
		InstanceId: instanceId,
	}
	resp, err := client.ListAccounts(arg)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetAccounts error", zap.Error(err))
		return nil
	}
	return resp.Result
}
func GetSecurityGroupRules(ctx context.Context, client *redis.Client, instanceId string) *redis.ListSecurityGroupsResponse {
	if client == nil {
		log.CtxLogger(ctx).Warn("redis AccountClient is nil")
		return nil
	}
	arg := &redis.ListSecurityGroupsRequest{
		InstanceId: instanceId,
	}
	resp, err := client.ListSecurityGroupActiveRules(arg)
	if err != nil {
		log.CtxLogger(ctx).Warn("GetSecurityGroupRules error", zap.Error(err))
		return nil
	}
	return resp
}
