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
	"encoding/json"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/slb"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"time"
)

func CreateBaseClient(region, endpoint, ak, sk string) (client *sdk.Client, err error) {
	request := requests.NewCommonRequest()
	request.SetReadTimeout(10 * time.Second)   // Set request ReadTimeout to 10 second.
	request.SetConnectTimeout(5 * time.Second) // Set request ConnectTimeout to 5 second.
	request.Method = requests.GET
	request.Domain = endpoint      // Location Service will not be enabled if the host is specified. For example, service with a Certification type-Bearer Token should be specified
	request.Version = "2019-05-10" // Specify product version
	request.Scheme = "https"       // Set request scheme. Default: http
	//request.ApiName = "GetOrganizationList"
	request.ApiName = "ListResourceGroup"
	request.QueryParams["Product"] = "ascm" // Specify product
	request.SetHTTPSInsecure(true)
	request.TransToAcsRequest()
	client, err = sdk.NewClientWithOptions(region, getSdkConfig(), credentials.NewAccessKeyCredential(ak, sk))

	return client, err
}

func CreateEcsClient(region, endpoint, ak, sk string) (client *ecs.Client, err error) {
	cli, err := ecs.NewClientWithAccessKey(region, ak, sk)
	cli.Domain = endpoint
	if err != nil {
		return nil, err
	}
	return cli, err
}

func CreateSlbClient(region, endpoint, ak, sk string) (client *slb.Client, err error) {
	// so it was not in cache - create service
	cli, err := slb.NewClientWithAccessKey(region, ak, sk)
	cli.Domain = endpoint
	if err != nil {
		return nil, err
	}
	return cli, err
}

func CreateVpcClient(region, endpoint, ak, sk string) (client *vpc.Client, err error) {
	// so it was not in cache - create client
	cli, err := vpc.NewClientWithAccessKey(region, ak, sk)
	cli.Domain = endpoint
	if err != nil {
		return nil, err
	}
	return cli, err
}

// CreateRamClient returns the client connection for Alicloud RAM client
func CreateRamClient(region, endpoint, ak, sk string) (*ram.Client, error) {
	cli, err := ram.NewClientWithAccessKey(region, ak, sk)
	cli.Domain = endpoint
	if err != nil {
		return nil, err
	}

	return cli, nil
}

// CreateOssClient returns the client connection for Alicloud OSS client
func CreateOssClient(region, ak, sk string) (*oss.Client, error) {
	cli, err := oss.New("oss-"+region+".aliyuncs.com", ak, sk)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

type Services struct {
	EcsClient      *ecs.Client
	VPCClient      *vpc.Client
	SlbClient      *slb.Client
	BaseClient     *sdk.Client
	OssClient      *oss.Client
	ResourceGroups []ResourceGroup
}

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
	param := cloudAccountParam.AliCloudPrivateCloudAccountAuthParam
	switch cloudAccountParam.ResourceType {
	case ECS, SecurityGroup:
		client, err := CreateEcsClient(param.Region, param.GetEndPointByResourceType(ECS), param.AK, param.SK)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init ecs client failed, err: %s", err))
			return err
		}
		s.EcsClient = client
	case VPC, EIP:
		client, err := CreateVpcClient(param.Region, param.GetEndPointByResourceType(VPC), param.AK, param.SK)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init vpc client failed, err: %s", err))
			return err
		}
		s.VPCClient = client
	case SLB:
		client, err := CreateSlbClient(param.Region, param.GetEndPointByResourceType(SLB), param.AK, param.SK)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init slb client failed, err: %s", err))
			return err
		}
		s.SlbClient = client

		baseClient, err := CreateBaseClient(param.Region, param.GetEndPointByResourceType(SLB), param.AK, param.SK)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init base client failed, err: %s", err))
			return err
		}
		s.BaseClient = baseClient

		group := ListResourceGroup(baseClient, param.GetEndPointByResourceType(SLB))
		s.ResourceGroups = group.Data
	case OSS:
		client, err := CreateOssClient(param.GetEndPointByResourceType(OSS), param.AK, param.SK)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init oss client failed, err: %s", err))
		}
		s.OssClient = client
	}

	return nil
}

func ListResourceGroup(client *sdk.Client, endPoint string) Response {
	request := requests.NewCommonRequest()
	request.SetReadTimeout(10 * time.Second)   // Set request ReadTimeout to 10 second.
	request.SetConnectTimeout(5 * time.Second) // Set request ConnectTimeout to 5 second.
	request.Method = requests.GET
	request.Domain = endPoint      // Location Service will not be enabled if the host is specified. For example, service with a Certification type-Bearer Token should be specified
	request.Version = "2019-05-10" // Specify product version
	request.Scheme = "https"       // Set request scheme. Default: http
	//request.ApiName = "GetOrganizationList"
	request.ApiName = "ListResourceGroup"
	request.QueryParams["Product"] = "ascm" // Specify product
	request.SetHTTPSInsecure(true)
	request.TransToAcsRequest()
	resp := responses.BaseResponse{}
	err := client.DoAction(request, &resp)
	if err != nil {
		log.GetWLogger().Error(err.Error())
	}

	r := Response{}

	_ = json.Unmarshal([]byte(resp.GetHttpContentString()), &r)

	return r
}

type Response struct {
	SuccessResponse bool            `json:"successResponse"`
	AsapiSuccess    bool            `json:"asapiSuccess"`
	Code            int             `json:"code"`
	Data            []ResourceGroup `json:"data"`
}

type ResourceGroup struct {
	OrganizationID int32 `json:"organizationId"`
	Id             int32 `json:"id"`
}

func getSdkConfig() *sdk.Config {
	return sdk.NewConfig().
		WithTimeout(time.Duration(30) * time.Second).
		WithEnableAsync(true).
		WithGoRoutinePoolSize(100).
		WithMaxTaskQueueSize(10000).
		WithDebug(false).
		WithScheme("HTTPS")
}
