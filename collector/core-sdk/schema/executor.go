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
	"github.com/core-sdk/config"
	"github.com/core-sdk/log"
	"github.com/core-sdk/utils"
	"errors"
	"fmt"
)

type Executor struct {
	opts config.Options

	platform *Platform

	client *Client

	registry Registry

	registered bool

	cloudRecLogger *CloudRecLogger
}

func RunExecutor(platform *Platform) (err error) {
	// load route from route.yaml
	err, options := config.LoadConfig()
	if err != nil {
		log.GetWLogger().Info(fmt.Sprintf("load route err %s", err.Error()))
		return
	}

	key, err := utils.GenerateAESKey()
	if err != nil {
		return
	}

	e := Executor{
		opts:     options,
		platform: platform,
		client: &Client{
			Platform:  platform.Name,
			ServerUrl: options.ServerUrl,
			OnceToken: options.AccessToken,
		},

		registry: Registry{
			Platform:      platform.Name,
			AgentName:     options.AgentName,
			Cron:          options.Cron,
			RegistryValue: utils.GenerateRegistryValue(),
			SecretKey:     key,
		},
	}

	err = e.Register()
	if err != nil && len(platform.DefaultCloudAccounts) == 0 {
		return
	}

	e.cloudRecLogger = InitCloudRecLogger(options.ServerUrl, options.AttentionErrorTexts)

	err = e.Start()

	return
}

func (e *Executor) Register() (err error) {
	resp, err := e.client.RegistryOnce(e.registry)
	if err != nil {
		return
	}

	if resp == nil {
		return errors.New("no persistent token is found and data cannot be pushed to the server")
	}

	e.platform.client = NewClientWithPersistentToken(e.platform.Name, e.opts.Sites, e.opts.ServerUrl, resp.PersistentToken)
	e.registered = true
	go func() {
		e.client.RegistryCycle(e.registry)
	}()
	return
}

func (e *Executor) SendSupportResourceType() {
	var supportResourceTypeList []SupportResource
	for _, resource := range e.platform.Resources {
		r := SupportResource{
			ResourceType:      resource.ResourceType,
			ResourceTypeName:  resource.ResourceTypeName,
			ResourceGroupType: resource.ResourceGroupType,
		}
		supportResourceTypeList = append(supportResourceTypeList, r)
	}

	e.platform.client.SendSupportResourceType(e.registry.RegistryValue, e.platform.Name, supportResourceTypeList)
}
