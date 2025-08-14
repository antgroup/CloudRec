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

package collector

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	"github.com/tencentyun/cos-go-sdk-v5"

	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	cdb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdb/v20170320"
	cfs "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cfs/v20190719"
	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	mariadb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/mariadb/v20170312"
	postgres "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/postgres/v20170312"
	sqlserver "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sqlserver/v20180328"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
)

type Services struct {
	Region     string
	Credential *common.Credential
	CVM        *cvm.Client
	CLB        *clb.Client
	CDB        *cdb.Client
	VPC        *vpc.Client
	MariaDB    *mariadb.Client
	PostgreSQL *postgres.Client
	SQLServer  *sqlserver.Client
	CAM        *cam.Client
	CFS        *cfs.Client
	COS        *cos.Client
	DNSPod     *dnspod.Client
}

// Clone creates a new instance of Services
func (s *Services) Clone() schema.ServiceInterface {
	// Create a new instance with copied basic information
	return &Services{}
}

// AssessCollectionTrigger determines whether asset collection should be performed for the cloud account
// Returns true if collection should proceed, false if it should be skipped
// This can be used to skip collection when credentials are invalid or no changes occurred
// AssessCollectionTrigger determines whether collection should be performed for the given cloud account
// Returns CollectRecordInfo containing collection decision and metadata
func (s *Services) AssessCollectionTrigger(param schema.CloudAccountParam) schema.CollectRecordInfo {
	// TODO: Implement logic to check if collection should be performed
	// For example:
	// - Check if credentials are valid
	// - Check if there were recent changes in the account
	// - Check if the last collection was recent enough
	// - Check if the account is in maintenance mode

	startTime := time.Now().Format("2006-01-02T15:04:05Z")
	recordInfo := schema.CollectRecordInfo{
		CloudAccountId:   param.CloudAccountId,
		Platform:         param.Platform,
		StartTime:        startTime,
		EndTime:          "",   // Will be set when collection completes
		EnableCollection: true, // Default implementation: always collect
	}

	return recordInfo
}

func (s *Services) InitServices(cloudAccountParam schema.CloudAccountParam) (err error) {
	param := cloudAccountParam.CommonCloudAccountParam
	s.Region = param.Region
	s.Credential = common.NewCredential(
		param.AK,
		param.SK,
	)

	switch cloudAccountParam.ResourceType {
	case CVM:
		s.CVM, err = createCVMClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize CVM client in region:%s, err:%s", param.Region, err.Error()))
		}
	case SecurityGroup, NATGateway:
		s.VPC, err = createVPCClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize SG client in region:%s, err:%s", param.Region, err.Error()))
		}
	case CLB:
		s.CLB, err = createCLBClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize CLB client in region:%s, err:%s", param.Region, err.Error()))
		}
	case CDB:
		s.CDB, err = createCDBClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize CDB client in region:%s, err:%s", param.Region, err.Error()))
		}
	case MariaDB:
		s.MariaDB, err = createMariaDBClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize MariaDB client in region:%s, err:%s", param.Region, err.Error()))
		}
	case PostgreSQL:
		s.PostgreSQL, err = createPostgreSQLClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize PostgreSQL client in region:%s, err:%s", param.Region, err.Error()))
		}
	case SQLServer:
		s.SQLServer, err = createSQLServerClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize SQLServer client in region:%s, err:%s", param.Region, err.Error()))
		}
	case CAMUser:
		s.CAM, err = createCAMClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize CAM client in region:%s, err:%s", param.Region, err.Error()))
		}
	case CFS:
		s.CFS, err = createCFSClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize CFS client in region:%s, err:%s", param.Region, err.Error()))
		}
	case Bucket:
		s.COS = createCOSClient(param.AK, param.SK)
	case DNSPod:
		s.DNSPod, err = createDNSClient(param.Region, s.Credential)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize DNSPod client in region:%s, err:%s", param.Region, err.Error()))
		}
	}

	return nil
}

func createCVMClient(region string, credential *common.Credential) (client *cvm.Client, err error) {

	// 实例化一个client选项，可选的，没有特殊需求可以跳过
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "cvm.tencentcloudapi.com"
	// 实例化要请求产品的client对象,clientProfile是可选的
	client, err = cvm.NewClient(credential, region, cpf)

	return client, err
}

func createVPCClient(region string, credential *common.Credential) (client *vpc.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "vpc.tencentcloudapi.com"
	client, err = vpc.NewClient(credential, region, cpf)
	return client, err
}

func createCLBClient(region string, credential *common.Credential) (client *clb.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "clb.tencentcloudapi.com"
	client, err = clb.NewClient(credential, region, cpf)
	return client, err
}

func createCDBClient(region string, credential *common.Credential) (client *cdb.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "cdb.tencentcloudapi.com"
	client, err = cdb.NewClient(credential, region, cpf)
	return client, err
}

func createMariaDBClient(region string, credential *common.Credential) (client *mariadb.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "mariadb.tencentcloudapi.com"
	client, err = mariadb.NewClient(credential, region, cpf)
	return client, err
}

func createPostgreSQLClient(region string, credential *common.Credential) (client *postgres.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "postgres.tencentcloudapi.com"
	client, err = postgres.NewClient(credential, region, cpf)
	return client, err
}

func createSQLServerClient(region string, credential *common.Credential) (client *sqlserver.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "sqlserver.tencentcloudapi.com"
	client, err = sqlserver.NewClient(credential, region, cpf)
	return client, err
}

func createCAMClient(region string, credential *common.Credential) (client *cam.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "cam.tencentcloudapi.com"
	client, err = cam.NewClient(credential, region, cpf)
	return client, err
}

func createCFSClient(region string, credential *common.Credential) (client *cfs.Client, err error) {

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "cfs.tencentcloudapi.com"
	client, err = cfs.NewClient(credential, region, cpf)
	return client, err
}

func createCOSClient(ak, sk string) (client *cos.Client) {

	u, _ := url.Parse("https://service.cos.myqcloud.com")
	b := &cos.BaseURL{ServiceURL: u}
	client = cos.NewClient(b, &http.Client{
		Transport: &cos.AuthorizationTransport{
			SecretID:  ak,
			SecretKey: sk,
		},
	})

	return client
}

func createDNSClient(region string, credential *common.Credential) (client *dnspod.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
	client, err = dnspod.NewClient(credential, region, cpf)

	return client, err
}
