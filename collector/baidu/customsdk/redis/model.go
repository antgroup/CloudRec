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

type ListAccountsRequest struct {
	InstanceId string
	// Version    string
}

// ListAccountsResponse - List 用于查询账号列表
type ListAccountsResponse struct {
	Result  []*Account `json:"result"`
	Success bool       `json:"success"`
}
type Account struct {
	UserName     string `json:"userName"`     // 账号名称
	UpdateStatus int    `json:"updateStatus"` // 集群 ID账号状态。0：正常可用；1：创建中；2：修改中；4：删除中；
	Extra        string `json:"extra"`        // 备注信息
	UserType     int    `json:"userType"`     // 账号权限。1：读写；2：只读；
}

// 安全组 https://cloud.baidu.com/doc/SCS/s/Mm35kietp
type ListSecurityGroupsRequest struct {
	InstanceId string
	Version    string
}
type ListSecurityGroupsResponse struct {
	Groups      []SecurityGroupDetail `json:"groups"`      // 安全组列表
	ActiveRules []SecurityGroupRule   `json:"activeRules"` // 安全组规则列表
}
type SecurityGroupDetail struct {
	SecurityGroupName   string              `json:"securityGroupName"`   // 安全组名称
	SecurityGroupID     string              `json:"securityGroupId"`     // 安全组ID
	SecurityGroupRemark string              `json:"securityGroupRemark"` // 安全组备注
	SecurityGroupUuid   string              `json:"securityGroupUuid"`   // 安全组长ID
	Outbound            []SecurityGroupRule `json:"outbound"`            // 安全组规则
	VpcName             string              `json:"vpcName"`             // vpc名称
	VpcID               string              `json:"vpcId"`               // vpcId
	ProjectID           string              `json:"projectId"`
}

type SecurityGroupRule struct {
	ID                  string `json:"id"`                  // 安全组规则ID
	SecurityGroupRuleID string `json:"securityGroupRuleId"` // 安全组规则ID
	SecurityGroupID     string `json:"securityGroupId"`     // 安全组ID
	SecurityGroupUuid   string `json:"securityGroupUuid"`   // 安全组长ID
	Direction           string `json:"direction"`           // 入站/出站，取值ingress/Ingress或egress/Egress
	Ethertype           string `json:"ethertype"`           // 网络类型，取值IPv4或IPv6。值为空时表示默认取值IPv4
	Protocol            string `json:"protocol"`            // 协议类型，tcp、udp或icmp，值为空时默认取值all
	PortRange           string `json:"portRange"`           // 端口范围，可以指定80等单个端口，值为空时默认取值1-65535
	RemoteGroupID       string `json:"remoteGroupId"`       // 源安全组ID
	RemoteGroupName     string `json:"remoteGroupName"`     // 源安全组名称
	RemoteIP            string `json:"remoteIP"`            // 源IP地址
	Name                string `json:"name"`                // 安全组规则名称
	TenantID            string `json:"tenantId"`
}
