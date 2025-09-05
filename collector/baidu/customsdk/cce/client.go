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

package cce

import (
	"github.com/baidubce/bce-sdk-go/bce"
)

const (
	URI_PREFIX        = bce.URI_PREFIX + "api/cce/service/v2"
	REMEDY_URI_PREFIX = bce.URI_PREFIX + "api/cce/remedy/v1"

	DEFAULT_ENDPOINT = "cce." + bce.DEFAULT_REGION + ".baidubce.com"

	REQUEST_RBAC_LIST_URL = "/rbac"
)

var _ Interface = &Client{}

// Client 实现 ccev2.Interface
type Client struct {
	*bce.BceClient
}

func NewClient(ak, sk, endPoint string) (*Client, error) {
	if len(endPoint) == 0 {
		endPoint = DEFAULT_ENDPOINT
	}
	client, err := bce.NewBceClientWithAkSk(ak, sk, endPoint)
	if err != nil {
		return nil, err
	}
	return &Client{client}, nil
}
func getRBACListURI() string {
	return URI_PREFIX + REQUEST_RBAC_LIST_URL
}
