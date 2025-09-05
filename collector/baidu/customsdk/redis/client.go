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
	"github.com/baidubce/bce-sdk-go/bce"
	"github.com/baidubce/bce-sdk-go/services/scs"
)

const (
	DEFAULT_ENDPOINT = "redis." + bce.DEFAULT_REGION + ".baidubce.com"
)

// Client of SCS service is a kind of BceClient, so derived from BceClient
type Client struct {
	*bce.BceClient
}

func NewClient(ak, sk, endPoint string) (*Client, error) {
	if len(endPoint) == 0 {
		endPoint = scs.DEFAULT_ENDPOINT
	}
	client, err := bce.NewBceClientWithAkSk(ak, sk, endPoint)
	if err != nil {
		return nil, err
	}
	return &Client{client}, nil
}

// List Account By Instance URL https://cloud.baidu.com/doc/SCS/s/almsu2odh
func getAccountWithInstanceIdUrl(instanceId string) string {
	return scs.INSTANCE_URL_V2 + "/" + instanceId + "/aclUserActions"
}

// List SecurityGroup By Instance URL https://cloud.baidu.com/doc/SCS/s/Mm35kietp
func getSecurityGroupWithInstanceIdUrl(instanceId string) string {
	return scs.INSTANCE_URL_V1 + "/" + instanceId + "/securityGroup"
}
