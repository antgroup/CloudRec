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

package schema

import (
	"encoding/json"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/utils"
	"go.uber.org/zap"
)

type CloudAccount struct {
	// baseinfo
	CloudAccountId string

	Platform string

	ResourceTypeList []string

	CredentialJson string

	CollectRecordId int64

	CollectRecordInfo CollectRecordInfo

	TaskId int64

	// proxy configuration,json format,such as: {"host":"127.0.0.1","port":"8080","username":"admin","password":"admin"}
	ProxyConfig string

	// common cloud account auth info
	CommonCloudAccountAuthParam CommonCloudAccountAuthParam

	// gcp cloud account auth info
	GCPCloudAccountAuthParam GCPCloudAccountAuthParam

	HwsPrivateCloudAccountAuthParam HwsPrivateCloudAccountAuthParam

	AliCloudPrivateCloudAccountAuthParam AliCloudPrivateCloudAccountAuthParam
}

// CommonCloudAccountAuthParam common cloud account auth info for
// alibaba cloud
// aws
// tencent cloud
// baidu cloud
// huawei cloud
type CommonCloudAccountAuthParam struct {
	AK     string
	SK     string
	Region string
}

type CloudAccountParam struct {
	CollectRecordInfo CollectRecordInfo

	// cloud account id
	CloudAccountId string

	// such as: "GCP", "AWS"...
	Platform string

	// such as: "EC2", "ECS", "RDS"...
	ResourceType string

	// proxy configuration,json format,such as:schema://user:password@host:port
	ProxyConfig string

	// task id
	TaskId int64

	// common cloud account auth info
	CommonCloudAccountParam CommonCloudAccountAuthParam

	// gcp cloud account auth info
	GCPCloudAccountParam GCPCloudAccountAuthParam

	HwsPrivateCloudAccountAuthParam HwsPrivateCloudAccountAuthParam

	AliCloudPrivateCloudAccountAuthParam AliCloudPrivateCloudAccountAuthParam
}

// GCPCloudAccountAuthParam GCP cloud account auth info
type GCPCloudAccountAuthParam struct {
	ProjectId       string
	CredentialsJson string
}

// AliCloudPrivateCloudAccountAuthParam ali cloud private cloud account auth info
type AliCloudPrivateCloudAccountAuthParam struct {
	AK       string
	SK       string
	Region   string
	Endpoint string
}

func (param AliCloudPrivateCloudAccountAuthParam) GetEndPointByResourceType(resourceType string) string {
	endpointMap := make(map[string]string)
	err := json.Unmarshal([]byte(param.Endpoint), &endpointMap)
	if err != nil {
		log.GetWLogger().Warn("The endpoint not a valid json.", zap.String("endpoint", param.Endpoint))
		return param.Endpoint
	}

	if value, ok := endpointMap[resourceType]; ok {
		return value
	} else {
		return ""
	}
}

// HwsPrivateCloudAccountAuthParam hws private cloud account auth info
type HwsPrivateCloudAccountAuthParam struct {
	AK          string
	SK          string
	Region      string
	ProjectId   string
	IamEndpoint string
	EcsEndpoint string
	ElbEndpoint string
	EvsEndpoint string
	VpcEndpoint string
	ObsEndpoint string
}

// Get cloud account operation parameters, compatible with multi-cloud
func getCloudAccountParam(cloudAccount CloudAccount, region string, resourceType string) (CloudAccountParam, error) {
	cloudAccountParam := CloudAccountParam{
		CloudAccountId:    cloudAccount.CloudAccountId,
		Platform:          cloudAccount.Platform,
		ResourceType:      resourceType,
		ProxyConfig:       cloudAccount.ProxyConfig,
		CollectRecordInfo: cloudAccount.CollectRecordInfo,
		TaskId:            cloudAccount.TaskId,
	}

	switch cloudAccount.Platform {
	case string(constant.GCP):
		cloudAccountParam.GCPCloudAccountParam = cloudAccount.GCPCloudAccountAuthParam
		return cloudAccountParam, nil
	case string(constant.AlibabaCloudPrivate):
		cloudAccountParam.AliCloudPrivateCloudAccountAuthParam = cloudAccount.AliCloudPrivateCloudAccountAuthParam
		cloudAccountParam.AliCloudPrivateCloudAccountAuthParam.Region = region
		return cloudAccountParam, nil
	case string(constant.HuaweiCloudPrivate):
		cloudAccountParam.HwsPrivateCloudAccountAuthParam = cloudAccount.HwsPrivateCloudAccountAuthParam
		cloudAccountParam.HwsPrivateCloudAccountAuthParam.Region = region
		return cloudAccountParam, nil
	default:
		cloudAccountParam.CommonCloudAccountParam = cloudAccount.CommonCloudAccountAuthParam
		cloudAccountParam.CommonCloudAccountParam.Region = region
		return cloudAccountParam, nil
	}
}

// Decrypt cloud account credentials, compatible with multi-cloud
func decryptCredentialsInfo(encryptCloudAccountList []CloudAccount, key string) (decryptCloudAccountList []CloudAccount) {
	decryptCloudAccountList = encryptCloudAccountList
	for i := range decryptCloudAccountList {
		decryptJSON, err := utils.Decrypt(decryptCloudAccountList[i].CredentialJson, key)
		if err != nil {
			log.GetWLogger().Error(err.Error())
			continue
		}

		var credentialMap map[string]string
		err = json.Unmarshal([]byte(decryptJSON), &credentialMap)
		if err != nil {
			log.GetWLogger().Error(err.Error())
			continue
		}

		switch decryptCloudAccountList[i].Platform {
		case string(constant.GCP):
			decryptCloudAccountList[i].GCPCloudAccountAuthParam.CredentialsJson = credentialMap["credential"]
			var temp map[string]string
			err = json.Unmarshal([]byte(credentialMap["credential"]), &temp)
			decryptCloudAccountList[i].GCPCloudAccountAuthParam.ProjectId = temp["project_id"]
		case string(constant.AlibabaCloudPrivate):
			param := AliCloudPrivateCloudAccountAuthParam{
				AK:       credentialMap["ak"],
				SK:       credentialMap["sk"],
				Endpoint: credentialMap["endpoint"],
				Region:   credentialMap["regionId"],
			}

			decryptCloudAccountList[i].AliCloudPrivateCloudAccountAuthParam = param
		case string(constant.HuaweiCloudPrivate):
			param := HwsPrivateCloudAccountAuthParam{
				AK:          credentialMap["ak"],
				SK:          credentialMap["sk"],
				ProjectId:   credentialMap["projectId"],
				Region:      credentialMap["regionId"],
				IamEndpoint: credentialMap["iamEndpoint"],
				EcsEndpoint: credentialMap["ecsEndpoint"],
				ElbEndpoint: credentialMap["elbEndpoint"],
				EvsEndpoint: credentialMap["evsEndpoint"],
				VpcEndpoint: credentialMap["vpcEndpoint"],
				ObsEndpoint: credentialMap["obsEndpoint"],
			}

			decryptCloudAccountList[i].HwsPrivateCloudAccountAuthParam = param
		default:
			param := CommonCloudAccountAuthParam{
				AK: credentialMap["ak"],
				SK: credentialMap["sk"],
			}
			decryptCloudAccountList[i].CommonCloudAccountAuthParam = param
		}
	}
	return decryptCloudAccountList
}

func GetCloudAccountAuthenticator(info interface{}) (res []CloudAccount, err error) {
	marshal, _ := json.Marshal(info)

	err = json.Unmarshal(marshal, &res)

	return res, nil
}
