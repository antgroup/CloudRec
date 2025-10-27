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
	"errors"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	apm "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/apm/v1"
	apmregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/apm/v1/region"
	cbr "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cbr/v1"
	cbrRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cbr/v1/region"
	cce "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3"
	cceRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/region"
	css "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/css/v1"
	cssRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/css/v1/region"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecsRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/region"
	eip "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2"
	elbRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v2/region"
	elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	evs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/evs/v2"
	evsRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/evs/v2/region"
	gaussdbfornosql "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/gaussdbfornosql/v3"
	gaussdbfornosqlRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/gaussdbfornosql/v3/region"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	lts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/lts/v2"
	ltsRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/lts/v2/region"
	nat "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2"
	natRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2/region"
	rds "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3"
	rdsRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3/region"
	sfs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sfsturbo/v1"
	sfsRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sfsturbo/v1/region"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3"
	vpcRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/region"
)

func (s *Services) OBSClient() (*obs.ObsClient, error) {
	client, err := obs.New(s.ConfigGlobalAuth.AK, s.ConfigGlobalAuth.SK, "https://obs.cn-east-3.myhuaweicloud.com")
	return client, err
}

func (s *Services) IAMClient() (*iam.IamClient, error) {
	r := region.NewRegion("cn-east-3", "https://iam.cn-east-3.myhuaweicloud.com")

	hcClient, err := iam.IamClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigGlobalAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := iam.NewIamClient(hcClient)
	return client, nil
}

func (s *Services) APMClient() (*apm.ApmClient, error) {
	client := apm.NewApmClient(
		apm.ApmClientBuilder().
			WithRegion(apmregion.ValueOf("cn-north-4")).
			WithCredential(s.ConfigBaseAuth).
			Build())

	return client, nil
}

func (s *Services) VPCClient(regionId string) (*vpc.VpcClient, error) {
	r, err := vpcRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("vpc no such region")
	}
	hcClient, err := vpc.VpcClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := vpc.NewVpcClient(hcClient)
	return client, nil
}

func (s *Services) ELbClient(regionId string) (*elb.ElbClient, error) {
	r, err := elbRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("elb no such region")
	}
	hcClient, err := elb.ElbClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := elb.NewElbClient(hcClient)
	return client, nil
}

func (s *Services) EipClient(regionId string) (*eip.EipClient, error) {
	r, err := vpcRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("eip no such region")
	}
	hcClient, err := eip.EipClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := eip.NewEipClient(hcClient)
	return client, nil
}

func (s *Services) ECSClient(regionId string) (*ecs.EcsClient, error) {
	r, err := ecsRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("ecs no such region")
	}
	hcClient, err := ecs.EcsClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := ecs.NewEcsClient(hcClient)
	return client, nil
}

func (s *Services) EVSClient(regionId string) (*evs.EvsClient, error) {
	r, err := evsRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("evs no such region")
	}
	hcClient, err := evs.EvsClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := evs.NewEvsClient(hcClient)
	return client, nil
}

func (s *Services) CBRClient(regionId string) (*cbr.CbrClient, error) {
	r, err := cbrRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("cbr no such region")
	}
	hcClient, err := cbr.CbrClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := cbr.NewCbrClient(hcClient)
	return client, nil
}

func (s *Services) SFSClient(regionId string) (*sfs.SFSTurboClient, error) {
	r, err := sfsRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("sfs no such region")
	}
	hcClient, err := sfs.SFSTurboClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := sfs.NewSFSTurboClient(hcClient)
	return client, nil
}

func (s *Services) NATClient(regionId string) (*nat.NatClient, error) {
	r, err := natRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("nat no such region")
	}
	hcClient, err := nat.NatClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := nat.NewNatClient(hcClient)
	return client, nil
}

func (s *Services) GaussDBClient(regionId string) (*gaussdbfornosql.GaussDBforNoSQLClient, error) {
	r, err := gaussdbfornosqlRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("gaussDB no such region")
	}
	hcClient, err := gaussdbfornosql.GaussDBforNoSQLClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := gaussdbfornosql.NewGaussDBforNoSQLClient(hcClient)
	return client, nil
}

func (s *Services) CSSClient(regionId string) (*css.CssClient, error) {
	r, err := cssRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("css no such region")
	}
	hcClient, err := css.CssClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := css.NewCssClient(hcClient)
	return client, nil
}

func (s *Services) LTSClient(regionId string) (*lts.LtsClient, error) {
	r, err := ltsRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("lts no such region")
	}
	hcClient, err := lts.LtsClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := lts.NewLtsClient(hcClient)
	return client, nil
}

func (s *Services) CCEClient(regionId string) (*cce.CceClient, error) {
	r, err := cceRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("lts no such region")
	}
	hcClient, err := cce.CceClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := cce.NewCceClient(hcClient)
	return client, nil
}

func (s *Services) RDSClient(regionId string) (*rds.RdsClient, error) {
	r, err := rdsRegion.SafeValueOf(regionId)
	if r == nil {
		return nil, errors.New("rds no such region")
	}
	hcClient, err := rds.RdsClientBuilder().
		WithRegion(r).
		WithCredential(s.ConfigBaseAuth).
		WithHttpConfig(getHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	client := rds.NewRdsClient(hcClient)
	return client, nil
}
