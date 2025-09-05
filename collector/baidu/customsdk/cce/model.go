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

// Interface 定义 CCE 自定义 SDK
type Interface interface {
	// RBAC 列表 https://cloud.baidu.com/doc/CCE/s/pm2sxa9in#rbac-%E5%88%97%E8%A1%A8
	ListRBACs(args *ListRBACsRequest) (*ListRBACsResponse, error)
}

// ClusterKeywordType 集群模糊查询字段
type ClusterKeywordType string

const (
	// ClusterKeywordTypeClusterName 集群模糊查询字段: ClusterName
	ClusterKeywordTypeClusterName ClusterKeywordType = "clusterName"
	// ClusterKeywordTypeClusterID 集群模糊查询字段: ClusterID
	ClusterKeywordTypeClusterID ClusterKeywordType = "clusterID"
)

// ClusterOrderBy 集群查询排序字段
type ClusterOrderBy string

const (
	// ClusterOrderByClusterName 集群查询排序字段: ClusterName
	ClusterOrderByClusterName ClusterOrderBy = "clusterName"
	// ClusterOrderByClusterID 集群查询排序字段: ClusterID
	ClusterOrderByClusterID ClusterOrderBy = "clusterID"
	// ClusterOrderByCreatedAt 集群查询排序字段: CreatedAt
	ClusterOrderByCreatedAt ClusterOrderBy = "createdAt"
)

// Order 集群查询排序
type Order string

const (
	// OrderASC 集群查询排序: 升序
	OrderASC Order = "ASC"
	// OrderDESC 集群查询排序: 降序
	OrderDESC Order = "DESC"
)

const (
	// PageNoDefault 分页查询默认页码
	PageNoDefault int = 1
	// PageSizeDefault 分页查询默认页面元素数目
	PageSizeDefault int = 10
)

type ListRBACsRequest struct {
	UserID string
}

// ListRBACsResponse - List 用户 RBAC 返回
type ListRBACsResponse struct {
	Data      []*RBAC `json:"data"`
	RequestID string  `json:"requestID"`
}
type RBAC struct {
	Role        string `json:"role"`      // RBAC 角色
	ClusterID   string `json:"clusterID"` // 集群 ID
	Namespace   string `json:"namespace"` // 命名空间，特殊取值 all
	ClusterName string `json:"clusterName"`
}
