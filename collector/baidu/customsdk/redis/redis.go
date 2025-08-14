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
	"fmt"

	"github.com/baidubce/bce-sdk-go/bce"
	"github.com/baidubce/bce-sdk-go/http"
)

// 账号列表 https://cloud.baidu.com/doc/SCS/s/almsu2odh
func (c *Client) ListAccounts(args *ListAccountsRequest) (*ListAccountsResponse, error) {
	if args == nil {
		return nil, fmt.Errorf("args is nil")
	}
	result := &ListAccountsResponse{}
	err := bce.NewRequestBuilder(c).
		WithMethod(http.GET).
		WithURL(getAccountWithInstanceIdUrl(args.InstanceId)).
		WithResult(result).
		Do()

	return result, err
}

// 安全组规则列表 https://cloud.baidu.com/doc/SCS/s/Mm35kietp
func (c *Client) ListSecurityGroupActiveRules(args *ListSecurityGroupsRequest) (*ListSecurityGroupsResponse, error) {
	if args == nil {
		return nil, fmt.Errorf("args is nil")
	}
	result := &ListSecurityGroupsResponse{}
	err := bce.NewRequestBuilder(c).
		WithMethod(http.GET).
		WithURL(getSecurityGroupWithInstanceIdUrl(args.InstanceId)).
		WithResult(result).
		Do()

	return result, err
}
