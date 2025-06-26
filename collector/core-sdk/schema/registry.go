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
	"github.com/core-sdk/log"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"time"
)

func (c *Client) RegistryCycle(registry Registry) {
	t := time.NewTimer(0)
	defer t.Stop()

	failCount := 0
	const maxFailCount = 50

	for {
		<-t.C
		t.Reset(10 * time.Second)
		func() {
			resp, err := c.RegistryOnce(registry)
			if err != nil {
				failCount++
				log.GetWLogger().Error(fmt.Sprintf("The actuator failed to register %s, Failure count: %d", err.Error(), failCount))
				if failCount >= maxFailCount {
					log.GetWLogger().Error("Exceeded maximum registration failures. The program is about to exit")
					panic("exit")
					return
				}
			} else {
				failCount = 0
			}

			if resp != nil && resp.Status == "exit" {
				log.GetWLogger().Info("The exit signal is received. The program is about to exit")
				panic("exit")
			}
		}()
	}
}

func (c *Client) RegistryOnce(registry Registry) (resp *RegistryResponse, err error) {
	t := time.NewTimer(time.Second * 0)
	defer t.Stop()
	param, err := json.Marshal(registry)
	if err != nil {
		log.GetWLogger().Error(fmt.Sprintf("The actuator failed to register %s", err.Error()))
	}

	t.Reset(time.Second * time.Duration(10))
	result, err := c.postWithOnceToken("/api/agent/registry", string(param), c.OnceToken)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.GetWLogger().Error(err.Error())
		}
	}(result.Body)
	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return nil, err
	}

	res := &res{}
	_ = json.Unmarshal(body, &res)
	if res.Code != constant.SuccessCode {
		log.GetWLogger().Warn(fmt.Sprintf("The actuator failed to register Error Msg: %s", res.Msg))
		if res.Msg != nil {
			return nil, errors.New(res.Msg.(string))
		}
		return nil, errors.New("unknown error")
	}

	marshal, err := json.Marshal(res.Content)

	err = json.Unmarshal(marshal, &resp)

	return
}
