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
	"fmt"

	"github.com/baidubce/bce-sdk-go/bce"
	"github.com/baidubce/bce-sdk-go/http"
)

// ListRBACs 集群列表 https://cloud.baidu.com/doc/CCE/s/pm2sxa9in#rbac-%E5%88%97%E8%A1%A8
func (c *Client) ListRBACs(args *ListRBACsRequest) (*ListRBACsResponse, error) {
	if args == nil {
		return nil, fmt.Errorf("args is nil")
	}
	result := &ListRBACsResponse{}
	err := bce.NewRequestBuilder(c).
		WithMethod(http.GET).
		WithURL(getRBACListURI()).
		WithQueryParamFilter("userID", args.UserID).
		WithResult(result).
		Do()

	return result, err
}
