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
	"context"
	"github.com/core-sdk/log"
	"go.uber.org/zap"
	"net"
	"time"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	cbr "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cbr/v1"
	cce "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3"
	css "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/css/v1"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	eip "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2"
	elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	evs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/evs/v2"
	gaussdbfornosql "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/gaussdbfornosql/v3"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	lts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/lts/v2"
	nat "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2"
	rds "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3"
	sfs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sfsturbo/v1"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
)

func ConfigBaseAuth(ak string, sk string) *basic.Credentials {
	auth, _ := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		SafeBuild()

	return auth
}
func ConfigGlobalAuth(ak string, sk string) *global.Credentials {
	auth, _ := global.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		SafeBuild()

	return auth
}

const (
	DefaultTimeout = 5 * time.Second
)

func getHttpConfig() (httpConfig *config.HttpConfig) {
	httpConfig = config.DefaultHttpConfig()
	httpConfig.WithIgnoreSSLVerification(true)
	httpConfig.WithTimeout(DefaultTimeout)
	dialContext := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}
	httpConfig.WithDialContext(dialContext)

	return httpConfig
}

type Services struct {
	Region           string
	ConfigBaseAuth   *basic.Credentials
	ConfigGlobalAuth *global.Credentials
	OBS              *obs.ObsClient
	IAM              *iam.IamClient
	ECS              *ecs.EcsClient
	VPC              *vpc.VpcClient
	ELB              *elb.ElbClient
	EVS              *evs.EvsClient
	GaussDBForNoSQL  *gaussdbfornosql.GaussDBforNoSQLClient
	LTS              *lts.LtsClient
	Nat              *nat.NatClient
	SFS              *sfs.SFSTurboClient
	CBR              *cbr.CbrClient
	CCE              *cce.CceClient
	CSS              *css.CssClient
	EIP              *eip.EipClient
	RDS              *rds.RdsClient
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
	if cloudAccountParam.Platform == string(constant.HuaweiCloud) {
		param := cloudAccountParam.CommonCloudAccountParam
		s.Region = param.Region
		s.ConfigGlobalAuth = ConfigGlobalAuth(param.AK, param.SK)
		s.ConfigBaseAuth = ConfigBaseAuth(param.AK, param.SK)
		switch cloudAccountParam.ResourceType {
		case Bucket:
			s.OBS, err = s.OBSClient()
		case ECS:
			s.ECS, err = s.ECSClient(param.Region)
		case IAMUser:
			s.IAM, err = s.IAMClient()
		case VPC, SecurityGroup:
			s.VPC, err = s.VPCClient(param.Region)
		case ELB:
			s.ELB, err = s.ELbClient(param.Region)
		case EVS:
			s.EVS, err = s.EVSClient(param.Region)
		case GaussDB:
			s.GaussDBForNoSQL, err = s.GaussDBClient(param.Region)
		case LTS:
			s.LTS, err = s.LTSClient(param.Region)
		case NatGateway:
			s.Nat, err = s.NATClient(param.Region)
		case SFSShare:
			s.SFS, err = s.SFSClient(param.Region)
		case CBR:
			s.CBR, err = s.CBRClient(param.Region)
		case CCE:
			s.CCE, err = s.CCEClient(param.Region)
		case CSS:
			s.CSS, err = s.CSSClient(param.Region)
		case EIP:
			s.EIP, err = s.EipClient(param.Region)
		case RDS:
			s.RDS, err = s.RDSClient(param.Region)
		}
	}

	if cloudAccountParam.Platform == string(constant.HuaweiCloudPrivate) {
		param := cloudAccountParam.HwsPrivateCloudAccountAuthParam
		s.Region = param.Region
		s.ConfigGlobalAuth = ConfigGlobalAuthForPrivate(param.AK, param.SK, param.IamEndpoint)
		s.ConfigBaseAuth = ConfigBaseAuthForPrivate(param.ProjectId, param.AK, param.SK, param.IamEndpoint)

		switch cloudAccountParam.ResourceType {
		case Bucket:
			s.OBS, err = s.OBSClientForPrivate(param.ObsEndpoint)
		case ECS, VPC, SecurityGroup:
			s.ECS, err = s.ECSClientForPrivate(param.Region, param.EcsEndpoint)
			s.VPC, err = s.VPCClientForPrivate(param.Region, param.VpcEndpoint)
		case IAMUser:
			s.IAM, err = s.IAMClientForPrivate(param.IamEndpoint)
		case ELB:
			s.ELB, err = s.ELbClientForPrivate(param.Region, param.ElbEndpoint)
		case EIP:
			s.EIP, err = s.EipClientForPrivate(param.Region, param.VpcEndpoint)
		}
	}

	if err != nil {
		log.GetWLogger().Warn("init huawei cloud services failed, err", zap.Error(err))
	}

	return err
}
