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
	"github.com/core-sdk/constant"
	"encoding/json"
)

type res struct {
	Code    int64       `json:"code"`
	Msg     interface{} `json:"msg"`
	Content interface{} `json:"content"`
}

type Registry struct {
	Platform           string   `json:"platform"`
	RegistryValue      string   `json:"registryValue"`
	CloudAccountIdList []string `json:"CloudAccountIdList"`
	Cron               string   `json:"cron"`
	AgentName          string   `json:"agentName"`
	SecretKey          string   `json:"secretKey"`
}

type RegistryResponse struct {
	PersistentToken string `json:"persistentToken"`
	Status          string `json:"status"`
}

type AccountParam struct {
	Platform      string   `json:"platform"`
	Sites         []string `json:"sites"`
	RegistryValue string   `json:"registryValue"`
	TaskIds       []int64  `json:"taskIds"`
}

type SupportResourceTypeListRequest struct {
	Platform      string            `json:"platform"`
	PlatformName  string            `json:"platformName"`
	RegistryValue string            `json:"registryValue"`
	ResourceList  []SupportResource `json:"resourceList"`
}

type SupportResource struct {
	ResourceType      string `json:"resourceType"`
	ResourceTypeName  string `json:"resourceTypeName"`
	ResourceGroupType string `json:"resourceGroupType"`
}

type DataPushRequest struct {
	Version              string              `json:"version"`
	CloudAccountId       string              `json:"cloudAccountId"`
	Platform             string              `json:"platform"`
	PlatformName         string              `json:"platformName"`
	ResourceType         string              `json:"resourceType"`
	ResourceTypeName     string              `json:"resourceTypeName"`
	ResourceGroupType    string              `json:"resourceGroupType"`
	DocLink              string              `json:"docLink"`
	ResourceInstancesAll []*ResourceInstance `json:"resourceInstancesAll"`
}

func ReturnGeneral() []byte {
	data := &res{
		Code: constant.SuccessCode,
		Msg:  "success",
	}

	str, _ := json.Marshal(data)
	return str
}
