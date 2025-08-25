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

package test

import (
	yundun_bastionhost20191209 "github.com/alibabacloud-go/yundun-bastionhost-20191209/v2/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"strconv"
)

//func main() {
//	p := schema.GetInstance(schema.PlatformConfig{
//		Name: string(constant.AlibabaCloud),
//		Resources: []schema.Resource{
//			GetYundunData(),
//		},
//
//		Service:        &collector.Services{},
//		DefaultRegions: []string{"cn-hangzhou"},
//	})
//
//	if err := schema.RunExecutor(p); err != nil {
//		log.GetWLogger().Error(err.Error())
//	}
//}

func GetYundunData() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.Yundun,
		ResourceTypeName:   collector.Yundun,
		ResourceGroupType:  constant.SECURITY,
		Desc:               `https://next.api.aliyun.com/api/Sls/2020-12-30/CreateProject?RegionId=cn-hangzhou&sdkStyle=dara&tab=DEMO&lang=GO`,
		ResourceDetailFunc: ListDescribeInstances,
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.Description",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Instance          *yundun_bastionhost20191209.DescribeInstancesResponseBodyInstances
	InstanceAttribute *yundun_bastionhost20191209.DescribeInstanceAttributeResponseBodyInstanceAttribute
	Databases         []*yundun_bastionhost20191209.ListDatabasesResponseBodyDatabases
	NetworkDomains    []*yundun_bastionhost20191209.ListNetworkDomainsResponseBodyNetworkDomains
	DatabaseAccounts  []*yundun_bastionhost20191209.ListDatabaseAccountsResponseBodyDatabaseAccounts
	Users             []*yundun_bastionhost20191209.ListUsersResponseBodyUsers
	UserGroups        []*yundun_bastionhost20191209.ListUserGroupsResponseBodyUserGroups
	HostsWithAccounts []*HostsWithAccountDetail
	policies          []PolicyDetail
}

type HostsWithAccountDetail struct {
	Hosts        *yundun_bastionhost20191209.ListHostsResponseBodyHosts
	HostAccounts []*yundun_bastionhost20191209.ListHostAccountsResponseBodyHostAccounts
}

type PolicyDetail struct {
	Policy        *yundun_bastionhost20191209.ListPoliciesResponseBodyPolicies
	PolicyDetails *yundun_bastionhost20191209.GetPolicyResponseBodyPolicy
}

func NewInt32Pointer(i int) *int32 {
	v := int32(i)
	return &v
}

func ListDescribeInstances(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).YUNDUN
	regionId := cli.RegionId
	var pageNumber = 1
	count := 0
	for {
		req := &yundun_bastionhost20191209.DescribeInstancesRequest{
			RegionId:   regionId,
			PageSize:   NewInt32Pointer(100),
			PageNumber: NewInt32Pointer(pageNumber),
		}
		response, err := cli.DescribeInstances(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("yundun ListDescribeInstances error", zap.Error(err))
			return err
		}
		if len(response.Body.Instances) == 0 {
			return nil
		}

		for _, instance := range response.Body.Instances {
			res <- Detail{
				Instance:          instance,
				InstanceAttribute: GetDescribeInstanceAttribute(ctx, service, cli.RegionId, instance.InstanceId),
				Databases:         ListDatabases(ctx, service, cli.RegionId, instance.InstanceId),
				NetworkDomains:    ListNetworkDomains(ctx, service, cli.RegionId, instance.InstanceId),
				DatabaseAccounts:  ListDatabaseAccounts(ctx, service, cli.RegionId, instance.InstanceId),
				Users:             ListUsers(ctx, service, cli.RegionId, instance.InstanceId),
				UserGroups:        ListUserGroups(ctx, service, cli.RegionId, instance.InstanceId),
				HostsWithAccounts: ListHostsWithAccount(ctx, service, cli.RegionId, instance.InstanceId),
				policies:          ListPolicies(ctx, service, cli.RegionId, instance.InstanceId),
			}
			count++
		}
		if int64(count) >= *response.Body.TotalCount {
			break
		}
		pageNumber = int(pageNumber) + 1
	}
	return nil
}

func GetDescribeInstanceAttribute(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) *yundun_bastionhost20191209.DescribeInstanceAttributeResponseBodyInstanceAttribute {
	cli := service.(*collector.Services).YUNDUN
	req := &yundun_bastionhost20191209.DescribeInstanceAttributeRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}

	response, err := cli.DescribeInstanceAttribute(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("DescribeInstanceAttribute error", zap.Error(err))
		return nil
	}
	return response.Body.InstanceAttribute
}

func ListHosts(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (hosts []*yundun_bastionhost20191209.ListHostsResponseBodyHosts) {

	cli := service.(*collector.Services).YUNDUN
	var pageNumber = 1
	req := &yundun_bastionhost20191209.ListHostsRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}

	count := 0
	for {
		req.SetPageSize(strconv.Itoa(100))
		req.SetPageNumber(strconv.Itoa(pageNumber))
		response, err := cli.ListHosts(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListHosts error", zap.Error(err))
			return nil
		}
		if len(response.Body.Hosts) == 0 {
			return nil
		}
		hosts = append(hosts, response.Body.Hosts...)
		if int32(count) >= *response.Body.TotalCount {
			break
		}
		count += len(response.Body.Hosts)
		pageNumber = int(pageNumber) + 1
	}
	return hosts
}

func ListHostsWithAccount(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (hostsWithAccounts []*HostsWithAccountDetail) {
	cli := service.(*collector.Services).YUNDUN
	req := &yundun_bastionhost20191209.ListHostsRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}
	response, err := cli.ListHosts(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("ListHosts error", zap.Error(err))
		return nil
	}
	if len(response.Body.Hosts) == 0 {
		return nil
	}

	for _, hostInfo := range response.Body.Hosts {
		hostId := hostInfo.HostId
		accounts := ListHostAccounts(ctx, service, regionId, instanceId, hostId)
		hostsWithAccountDetail := HostsWithAccountDetail{Hosts: hostInfo, HostAccounts: accounts}
		hostsWithAccounts = append(hostsWithAccounts, &hostsWithAccountDetail)
	}
	return hostsWithAccounts
}

func ListDatabases(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (databases []*yundun_bastionhost20191209.ListDatabasesResponseBodyDatabases) {
	cli := service.(*collector.Services).YUNDUN
	var pageNumber = 1
	req := &yundun_bastionhost20191209.ListDatabasesRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}
	count := 0
	for {
		req.SetPageSize(strconv.Itoa(100))
		req.SetPageNumber(strconv.Itoa(pageNumber))
		response, err := cli.ListDatabases(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListDatabases error", zap.Error(err))
			return
		}
		if len(response.Body.Databases) == 0 {
			return nil
		}
		databases = append(databases, response.Body.Databases...)
		if int64(count) >= *response.Body.TotalCount {
			break
		}
		count += len(response.Body.Databases)
		pageNumber = int(pageNumber) + 1
	}
	return databases
}

func ListNetworkDomains(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (networkDomains []*yundun_bastionhost20191209.ListNetworkDomainsResponseBodyNetworkDomains) {

	cli := service.(*collector.Services).YUNDUN
	var pageNumber = 1
	req := &yundun_bastionhost20191209.ListNetworkDomainsRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}

	count := 0
	for {
		req.SetPageSize(strconv.Itoa(100))
		req.SetPageNumber(strconv.Itoa(pageNumber))
		response, err := cli.ListNetworkDomains(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListNetworkDomains error", zap.Error(err))
			return
		}
		if len(response.Body.NetworkDomains) == 0 {
			return nil
		}
		networkDomains = append(networkDomains, response.Body.NetworkDomains...)
		if int64(count) >= *response.Body.TotalCount {
			break
		}
		count += len(response.Body.NetworkDomains)
		pageNumber = int(pageNumber) + 1
	}
	return networkDomains
}

func ListHostAccounts(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string, HostId *string) (hostAccounts []*yundun_bastionhost20191209.ListHostAccountsResponseBodyHostAccounts) {
	cli := service.(*collector.Services).YUNDUN
	var pageNumber = 1
	req := &yundun_bastionhost20191209.ListHostAccountsRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
		HostId:     HostId,
	}
	count := 0
	for {
		req.SetPageSize(strconv.Itoa(100))
		req.SetPageNumber(strconv.Itoa(pageNumber))
		response, err := cli.ListHostAccounts(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListHostAccounts error", zap.Error(err))
			return
		}
		if len(response.Body.HostAccounts) == 0 {
			return nil
		}
		hostAccounts = append(hostAccounts, response.Body.HostAccounts...)
		if int32(count) >= *response.Body.TotalCount {
			break
		}
		count += len(response.Body.HostAccounts)
		pageNumber = int(pageNumber) + 1
	}
	return hostAccounts
}

func ListDatabaseAccounts(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (databaseAccounts []*yundun_bastionhost20191209.ListDatabaseAccountsResponseBodyDatabaseAccounts) {

	cli := service.(*collector.Services).YUNDUN
	var pageNumber = 1
	req := &yundun_bastionhost20191209.ListDatabaseAccountsRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}
	count := 0
	for {
		req.SetPageSize(strconv.Itoa(100))
		req.SetPageNumber(strconv.Itoa(pageNumber))
		response, err := cli.ListDatabaseAccounts(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListDatabaseAccounts error", zap.Error(err))
			return
		}
		if len(response.Body.DatabaseAccounts) == 0 {
			return nil
		}
		databaseAccounts = append(databaseAccounts, response.Body.DatabaseAccounts...)
		if int64(count) >= *response.Body.TotalCount {
			break
		}
		count += len(response.Body.DatabaseAccounts)
		pageNumber = int(pageNumber) + 1
	}
	return databaseAccounts
}

func ListUsers(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (users []*yundun_bastionhost20191209.ListUsersResponseBodyUsers) {
	cli := service.(*collector.Services).YUNDUN
	var pageNumber = 1
	req := &yundun_bastionhost20191209.ListUsersRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}
	count := 0
	for {
		req.SetPageSize(strconv.Itoa(100))
		req.SetPageNumber(strconv.Itoa(pageNumber))
		response, err := cli.ListUsers(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListUsers error", zap.Error(err))
			return
		}
		if len(response.Body.Users) == 0 {
			return nil
		}
		users = append(users, response.Body.Users...)
		if int32(count) >= *response.Body.TotalCount {
			break
		}
		count += len(response.Body.Users)
		pageNumber = int(pageNumber) + 1
	}
	return users
}

func ListUserGroups(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (userGroups []*yundun_bastionhost20191209.ListUserGroupsResponseBodyUserGroups) {
	cli := service.(*collector.Services).YUNDUN
	var pageNumber = 1
	req := &yundun_bastionhost20191209.ListUserGroupsRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}
	count := 0
	for {
		req.SetPageSize(strconv.Itoa(100))
		req.SetPageNumber(strconv.Itoa(pageNumber))
		response, err := cli.ListUserGroups(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("ListUserGroups error", zap.Error(err))
			return
		}
		if len(response.Body.UserGroups) == 0 {
			return nil
		}
		userGroups = append(userGroups, response.Body.UserGroups...)
		if int32(count) >= *response.Body.TotalCount {
			break
		}
		count += len(response.Body.UserGroups)
		pageNumber = int(pageNumber) + 1
	}
	return userGroups
}

func ListPolicies(ctx context.Context, service schema.ServiceInterface, regionId *string, instanceId *string) (policies []PolicyDetail) {
	cli := service.(*collector.Services).YUNDUN
	req := &yundun_bastionhost20191209.ListPoliciesRequest{
		RegionId:   regionId,
		InstanceId: instanceId,
	}
	response, err := cli.ListPolicies(req)
	if err != nil {
		log.CtxLogger(ctx).Warn("yundun ListPolicies error", zap.Error(err))
		return
	}
	return GetPolicyDetails(ctx, cli, regionId, instanceId, response.Body.Policies)
}

func GetPolicyDetails(ctx context.Context, cli *yundun_bastionhost20191209.Client, regionId *string, instanceId *string, policies []*yundun_bastionhost20191209.ListPoliciesResponseBodyPolicies) (resultPolicies []PolicyDetail) {
	for i := 0; i < len(policies); i++ {
		req := &yundun_bastionhost20191209.GetPolicyRequest{
			RegionId:   regionId,
			InstanceId: instanceId,
			PolicyId:   policies[i].PolicyId,
		}
		resp, err := cli.GetPolicy(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("yundun GetPolicy error", zap.Error(err))
			continue
		}
		p := PolicyDetail{
			Policy:        policies[i],
			PolicyDetails: resp.Body.Policy,
		}
		resultPolicies = append(resultPolicies, p)
	}

	return resultPolicies
}
