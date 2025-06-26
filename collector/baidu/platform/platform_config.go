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
	"github.com/cloudrec/baidu/collector"
	"github.com/cloudrec/baidu/collector/bcc"
	"github.com/cloudrec/baidu/collector/blb"
	"github.com/cloudrec/baidu/collector/bls"
	"github.com/cloudrec/baidu/collector/bos"
	"github.com/cloudrec/baidu/collector/cce"
	"github.com/cloudrec/baidu/collector/ccr"
	"github.com/cloudrec/baidu/collector/cfw"
	"github.com/cloudrec/baidu/collector/eip"
	"github.com/cloudrec/baidu/collector/iam"
	"github.com/cloudrec/baidu/collector/rds"
	"github.com/cloudrec/baidu/collector/redis"
	"github.com/cloudrec/baidu/collector/vpc"
	"github.com/cloudrec/baidu/collector/vpc/security_group"
)

func GetPlatformConfig() *schema.Platform {
	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.BaiduCloud),
		Resources: []schema.Resource{
			security_group.GetResource(),
			vpc.GetResource(),
			blb.GetResource(),
			blb.GetAppBLBResource(),
			bcc.GetResource(),
			bos.GetResource(),
			rds.GetResource(),
			eip.GetResource(),
			iam.GetResource(),
			cce.GetResource(),
			redis.GetResource(),
			ccr.GetResource(),
			bls.GetResource(),
			cfw.GetResource(),
		},

		Service:        &collector.Services{},
		DefaultRegions: []string{"bcc.bj.baidubce.com"},
	})
}
