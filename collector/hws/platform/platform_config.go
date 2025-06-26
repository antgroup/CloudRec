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

package platform

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"github.com/cloudrec/hws/collector"
	"github.com/cloudrec/hws/collector/cbr"
	"github.com/cloudrec/hws/collector/cce"
	"github.com/cloudrec/hws/collector/css"
	"github.com/cloudrec/hws/collector/ecs"
	"github.com/cloudrec/hws/collector/eip"
	"github.com/cloudrec/hws/collector/elb"
	"github.com/cloudrec/hws/collector/evs"
	"github.com/cloudrec/hws/collector/gaussdb"
	"github.com/cloudrec/hws/collector/iam"
	"github.com/cloudrec/hws/collector/lts"
	"github.com/cloudrec/hws/collector/nat"
	"github.com/cloudrec/hws/collector/obs"
	"github.com/cloudrec/hws/collector/rds"
	"github.com/cloudrec/hws/collector/sfs"
	"github.com/cloudrec/hws/collector/vpc"
)

func GetPlatformConfig() *schema.Platform {

	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.HuaweiCloud),
		Resources: []schema.Resource{
			vpc.GetVPCResource(),
			vpc.GetSecurityGroupResource(),
			sfs.GetShareResource(),
			obs.GetResource(),
			nat.GetGatewayResource(),
			iam.GetUserResource(),
			evs.GetVolumeResource(),
			elb.GetELBInstanceResource(),
			eip.GetEIPResource(),
			ecs.GetInstanceResource(),
			gaussDB.GetResource(),
			css.GetClusterResource(),
			cce.GetClusterResource(),
			cbr.GetVaultResource(),
			lts.GetResource(),
			rds.GetRDSInstanceResource(),
		},

		Service: &collector.Services{},
		DefaultRegions: []string{"cn-east-2", "cn-east-5", "cn-east-3", "cn-east-4", "cn-north-1", "cn-north-2", "cn-north-4", "cn-north-9", "cn-south-1" +
			"cn-south-2", "cn-southwest-2", "ap-southeast-1"},
	})

}

func GetPrivatePlatformConfig() *schema.Platform {

	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.HuaweiCloudPrivate),
		Resources: []schema.Resource{
			vpc.GetVPCResource(),
			vpc.GetSecurityGroupResource(),
			obs.GetResource(),
			iam.GetUserResource(),
			elb.GetELBInstanceResource(),
			eip.GetEIPResource(),
			ecs.GetInstanceResource(),
		},

		Service:        &collector.Services{},
		DefaultRegions: []string{"cn-east-2"},
	})

}
