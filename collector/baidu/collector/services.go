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
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"fmt"
	"github.com/baidubce/bce-sdk-go/services/appblb"
	"github.com/baidubce/bce-sdk-go/services/bcc"
	"github.com/baidubce/bce-sdk-go/services/blb"
	"github.com/baidubce/bce-sdk-go/services/bls"
	"github.com/baidubce/bce-sdk-go/services/bos"
	v2 "github.com/baidubce/bce-sdk-go/services/cce/v2"
	"github.com/baidubce/bce-sdk-go/services/cfw"
	"github.com/baidubce/bce-sdk-go/services/eccr"
	"github.com/baidubce/bce-sdk-go/services/eip"
	"github.com/baidubce/bce-sdk-go/services/iam"
	"github.com/baidubce/bce-sdk-go/services/rds"
	"github.com/baidubce/bce-sdk-go/services/scs"
	"github.com/baidubce/bce-sdk-go/services/vpc"
	"github.com/baidubce/bce-sdk-go/services/vpn"
)

type Services struct {
	VPCClient    *vpc.Client
	BCCClient    *bcc.Client
	BLBClient    *blb.Client
	APPBLBClient *appblb.Client
	BOSClient    *bos.Client
	RDSClient    *rds.Client
	EIPClient    *eip.Client
	IAMClient    *iam.Client
	CCEClient    *v2.Client
	RedisClient  *scs.Client
	CCRClient    *eccr.Client
	ECCRClient   *eccr.Client
	BLSClient    *bls.Client
	CFWClient    *cfw.Client
	VPNClient    *vpn.Client
}

// Clone creates a new instance of Services
func (s *Services) Clone() schema.ServiceInterface {
	// Return a new empty instance
	// All clients will be initialized when InitServices is called
	return &Services{}
}

func (s *Services) InitServices(cloudAccountParam schema.CloudAccountParam) (err error) {
	param := cloudAccountParam.CommonCloudAccountParam
	switch cloudAccountParam.ResourceType {
	case SECURITY_GROUP, BCC:
		SgClient, err := bcc.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init sg client failed, err: %s", err))
		}
		s.BCCClient = SgClient
	case VPC:
		vpcClient, err := vpc.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init vpc client failed, err: %s", err))
		}
		s.VPCClient = vpcClient
	case BLB:
		blbClient, err := blb.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init blb client failed, err: %s", err))
		}
		s.BLBClient = blbClient
	case APPBLB:
		appblbClient, err := appblb.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init appblbClient client failed, err: %s", err))
		}
		s.APPBLBClient = appblbClient
	case BOS:
		bosClient, err := bos.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init bos client failed, err: %s", err))
		}
		s.BOSClient = bosClient
	case RDS:
		rdsClient, err := rds.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init rds client failed, err: %s", err))
		}
		s.RDSClient = rdsClient

	case EIP:
		eipClient, err := eip.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init eip client failed, err: %s", err))
		}
		s.EIPClient = eipClient
	case IAM:
		iamClient, err := iam.NewClient(param.AK, param.SK)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init iam client failed, err: %s", err))
		}
		s.IAMClient = iamClient
	case CCE:
		cceClient, err := v2.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init cce client failed, err: %s", err))
		}
		s.CCEClient = cceClient
	case Redis:
		redisClient, err := scs.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init redis client failed, err: %s", err))
		}
		s.RedisClient = redisClient
	case CCR:
		ccrClient, err := eccr.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init ccr client failed, err: %s", err))
		}
		s.CCRClient = ccrClient

	case BLS:
		blsClient, err := bls.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init bls client failed, err: %s", err))
		}
		s.BLSClient = blsClient
	case CFW:
		cfwClient, err := cfw.NewClient(param.AK, param.SK, param.Region)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("init bls client failed, err: %s", err))
		}
		s.CFWClient = cfwClient
	}

	return nil
}
