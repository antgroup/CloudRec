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
	"strings"

	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"

	"github.com/KscSDK/ksc-sdk-go/ksc"
	"github.com/KscSDK/ksc-sdk-go/ksc/utils"
	cdn "github.com/KscSDK/ksc-sdk-go/service/cdnv1"
	eip "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/eip/v20160304"
	epc "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/epc/v20151101"
	iam "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/iam/v20151101"
	kce "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kce/v20231115"
	kce2 "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kce2/v20230101"
	kcm "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kcm/v20160304"
	kcrs "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kcrs/v20211109"
	kcs "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kcs/v20160701"
	kead "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kead/v20200101"
	kec "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kec/v20160304"
	kes "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/kes/v20201215"
	klog "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/klog/v20200731"
	knad "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/knad/v20230323"
	krds "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/krds/v20160701"
	postgresql "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/postgresql/v20181225"
	rabbitmq "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/rabbitmq/v20191017"
	slb "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/slb/v20160304"
	sqlserver "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/sqlserver/v20190425"
	vpc "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/vpc/v20160304"
	waf "github.com/kingsoftcloud/sdk-go/v2/ksyun/client/waf/v20200707"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common"
	"github.com/kingsoftcloud/sdk-go/v2/ksyun/common/profile"
	"github.com/ks3sdklib/aws-sdk-go/aws"
	"github.com/ks3sdklib/aws-sdk-go/aws/credentials"
	"github.com/ks3sdklib/aws-sdk-go/service/s3"
)

const apiEndpointSuffix = ".api.ksyun.com"
const s3EndpointSuffix = ".ksyuncs.com"

var s3_region_map = map[string]string{
	"BEIJING":     "ks3-cn-beijing",
	"SHANGHAI":    "ks3-cn-shanghai",
	"GUANGZHOU":   "ks3-cn-guangzhou",
	"SINGAPORE":   "ks3-sgp",
	"JR_SHANGHAI": "ks3-jr-shanghai",
	"JR_BEIJING":  "ks3-jr-beijing",
	"default":     "ks3-cn-beijing",
}

type Services struct {
	Credential *common.Credential
	VPC        *vpc.Client
	EIP        *eip.Client
	KEC        *kec.Client
	SLB        *slb.Client
	EPC        *epc.Client
	KCE        *kce.Client
	KCE2       *kce2.Client
	KCRS       *kcrs.Client
	KRDS       *krds.Client
	KCS        *kcs.Client
	PostgreSQL *postgresql.Client
	SQLServer  *sqlserver.Client
	KS3        *s3.S3
	CDN        *cdn.Cdnv1
	KLOG       *klog.Client
	IAM        *iam.Client
	RabbitMQ   *rabbitmq.Client
	KES        *kes.Client
	KCM        *kcm.Client
	WAF        *waf.Client
	KNAD       *knad.Client
	KEAD       *kead.Client
}

// Clone creates a new instance of Services
func (s *Services) Clone() schema.ServiceInterface {
	// Create a new instance with copied basic information
	return &Services{}
}

func (s *Services) InitServices(cloudAccountParam schema.CloudAccountParam) (err error) {
	param := cloudAccountParam.CommonCloudAccountParam
	s.Credential = common.NewCredential(
		param.AK,
		param.SK,
	)
	domain := apiEndpointSuffix

	switch cloudAccountParam.ResourceType {
	case VPC, SecurityGroup, NAT:
		s.VPC, err = createVPCClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize VPC client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KEC, KFS:
		s.KEC, err = createKECClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KEC client in region:%s, err:%s", param.Region, err.Error()))
		}
	case SLB, ALB:
		s.SLB, err = createSLBClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize SLB client in region:%s, err:%s", param.Region, err.Error()))
		}
	case EPC:
		s.EPC, err = createEPCClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize EPC client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KCE:
		s.KCE, err = createKCEClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KCE client in region:%s, err:%s", param.Region, err.Error()))
			break
		}
		s.KCE2, err = createKCE2Client(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KCE2 client in region:%s, err:%s", param.Region, err.Error()))
			break
		}
	case KCRS:
		s.KCRS, err = createKCRSClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KCRS client in region:%s, err:%s", param.Region, err.Error()))
		}
	case EIP:
		s.EIP, err = createEIPClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize EIP client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KRDS:
		s.KRDS, err = createKRDSClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KRDS client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KCS:
		s.KCS, err = createKCSClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KCS client in region:%s, err:%s", param.Region, err.Error()))
		}
	case PostgreSQL:
		s.PostgreSQL, err = createPostgreSQLClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize PostgreSQL client in region:%s, err:%s", param.Region, err.Error()))
		}
	case SQLServer:
		s.SQLServer, err = createSQLServerClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize SQLServer client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KS3:
		domain = s3EndpointSuffix
		s.KS3, err = createS3Client(param.Region, credentials.NewStaticCredentials(param.AK, param.SK, ""), domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KS3 client in region:%s, err:%s", param.Region, err.Error()))
		}
	case CDN:
		info := &utils.UrlInfo{CustomerDomain: strings.TrimPrefix(domain, ".")}
		s.CDN = cdn.SdkNew(ksc.NewClient(param.AK, param.SK, false), &ksc.Config{Region: &param.Region}, info)
	case KLOG:
		s.KLOG, err = createKLOGClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KLOG client in region:%s, err:%s", param.Region, err.Error()))
		}
	case IAMUser, IAMRole:
		s.IAM, err = createIAMClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize IAM client in region:%s, err:%s", param.Region, err.Error()))
		}
	case RabbitMQ:
		s.RabbitMQ, err = createRabbitMQClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize RabbitMQ client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KES:
		s.KES, err = createKESClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KES client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KCM:
		s.KCM, err = createKCMClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KCM client in region:%s, err:%s", param.Region, err.Error()))
		}
	case WAF:
		s.WAF, err = createWAFClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize WAF client in region:%s, err:%s", param.Region, err.Error()))
		}
	case KNAD:
		s.KNAD, err = createKNADClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KNAD client in region:%s, err:%s", param.Region, err.Error()))
		}
		s.KEAD, err = createKEADClient(param.Region, s.Credential, domain)
		if err != nil {
			log.GetWLogger().Error(fmt.Sprintf("failed to initialize KNAD client in region:%s, err:%s", param.Region, err.Error()))
		}
	}

	return nil
}

func createVPCClient(region string, credential *common.Credential, domain string) (client *vpc.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "vpc" + domain
	client, err = vpc.NewClient(credential, region, cpf)
	return client, err
}

func createSLBClient(region string, credential *common.Credential, domain string) (client *slb.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "slb" + domain
	client, err = slb.NewClient(credential, region, cpf)
	return client, err
}

func createKECClient(region string, credential *common.Credential, domain string) (client *kec.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kec" + domain
	client, err = kec.NewClient(credential, region, cpf)
	return client, err
}

func createEPCClient(region string, credential *common.Credential, domain string) (client *epc.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "epc" + domain
	client, err = epc.NewClient(credential, region, cpf)
	return client, err
}

func createKCEClient(region string, credential *common.Credential, domain string) (client *kce.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kce" + domain
	client, err = kce.NewClient(credential, region, cpf)
	return client, err
}

func createKCE2Client(region string, credential *common.Credential, domain string) (client *kce2.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kce2" + domain
	client, err = kce2.NewClient(credential, region, cpf)
	return client, err
}

func createKCRSClient(region string, credential *common.Credential, domain string) (client *kcrs.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kcrs" + domain
	client, err = kcrs.NewClient(credential, region, cpf)
	return client, err
}

func createEIPClient(region string, credential *common.Credential, domain string) (client *eip.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "eip" + domain
	client, err = eip.NewClient(credential, region, cpf)
	return client, err
}

func createKRDSClient(region string, credential *common.Credential, domain string) (client *krds.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "krds" + domain
	client, err = krds.NewClient(credential, region, cpf)
	return client, err
}

func createKCSClient(region string, credential *common.Credential, domain string) (client *kcs.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kcs" + domain
	client, err = kcs.NewClient(credential, region, cpf)
	return client, err
}

func createPostgreSQLClient(region string, credential *common.Credential, domain string) (client *postgresql.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "postgresql" + domain
	client, err = postgresql.NewClient(credential, region, cpf)
	return client, err
}

func createSQLServerClient(region string, credential *common.Credential, domain string) (client *sqlserver.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "sqlserver" + domain
	client, err = sqlserver.NewClient(credential, region, cpf)
	return client, err
}

func createS3Client(region string, credential *credentials.Credentials, domain string) (client *s3.S3, err error) {
	prefix, ok := s3_region_map[region]
	if !ok {
		return nil, fmt.Errorf("region:%s not supported", region)
	}
	return s3.New(&aws.Config{
		Region:      region,
		Credentials: credential,
		Endpoint:    prefix + domain,
	}), nil
}

func createKLOGClient(region string, credential *common.Credential, domain string) (client *klog.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "klog" + domain
	client, err = klog.NewClient(credential, region, cpf)
	return client, err
}

func createIAMClient(region string, credential *common.Credential, domain string) (client *iam.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "iam" + domain
	client, err = iam.NewClient(credential, region, cpf)
	return client, err
}

func createRabbitMQClient(region string, credential *common.Credential, domain string) (client *rabbitmq.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "rabbitmq" + domain
	client, err = rabbitmq.NewClient(credential, region, cpf)
	return client, err
}

func createKESClient(region string, credential *common.Credential, domain string) (client *kes.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kes" + domain
	client, err = kes.NewClient(credential, region, cpf)
	return client, err
}

func createKCMClient(region string, credential *common.Credential, domain string) (client *kcm.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kcm" + domain
	client, err = kcm.NewClient(credential, region, cpf)
	return client, err
}

func createWAFClient(region string, credential *common.Credential, domain string) (client *waf.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "POST"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "waf" + domain
	client, err = waf.NewClient(credential, region, cpf)
	return client, err
}

func createKNADClient(region string, credential *common.Credential, domain string) (client *knad.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "knad" + domain
	client, err = knad.NewClient(credential, region, cpf)
	return client, err
}

func createKEADClient(region string, credential *common.Credential, domain string) (client *kead.Client, err error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqMethod = "GET"
	// 设置超时时间  可不设置
	cpf.HttpProfile.ReqTimeout = 60
	// 请求域名
	cpf.HttpProfile.Endpoint = "kead" + domain
	client, err = kead.NewClient(credential, region, cpf)
	return client, err
}
