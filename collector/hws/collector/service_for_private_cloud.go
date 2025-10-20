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
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	eip "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2"
	elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"

	// vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3"
)

func ConfigBaseAuthForPrivate(projectId, ak, sk, endpoint string) *basic.Credentials {
	auth, _ := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		WithIamEndpointOverride(endpoint).
		// private cloud need route iam endpoint override
		WithProjectId(projectId).
		SafeBuild()

	return auth
}

func ConfigGlobalAuthForPrivate(ak, sk, endpoint string) *global.Credentials {
	auth, _ := global.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		WithIamEndpointOverride(endpoint).
		SafeBuild()

	return auth
}

func (s *Services) VPCClientForPrivate(regionId, endpoint string) (*vpc.VpcClient, error) {
	r := region.NewRegion(regionId, endpoint)
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

func (s *Services) ELbClientForPrivate(regionId, endpoint string) (*elb.ElbClient, error) {
	r := region.NewRegion(regionId, endpoint)

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

func (s *Services) EipClientForPrivate(regionId, endpoint string) (*eip.EipClient, error) {
	r := region.NewRegion(regionId, endpoint)
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

func (s *Services) ECSClientForPrivate(regionId, endpoint string) (*ecs.EcsClient, error) {
	r := region.NewRegion(regionId, endpoint)
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

func (s *Services) OBSClientForPrivate(endpoint string) (*obs.ObsClient, error) {
	client, err := obs.New(s.ConfigGlobalAuth.AK, s.ConfigGlobalAuth.SK, endpoint)
	return client, err
}

func (s *Services) IAMClientForPrivate(endpoint string) (*iam.IamClient, error) {
	r := region.NewRegion("cn-east-3", endpoint)

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
