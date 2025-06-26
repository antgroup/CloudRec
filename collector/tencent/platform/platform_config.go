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
	"github.com/cloudrec/tencent/collector"
	"github.com/cloudrec/tencent/collector/cam"
	"github.com/cloudrec/tencent/collector/cdb"
	"github.com/cloudrec/tencent/collector/cfs"
	"github.com/cloudrec/tencent/collector/clb"
	"github.com/cloudrec/tencent/collector/cos"
	"github.com/cloudrec/tencent/collector/cvm"
	"github.com/cloudrec/tencent/collector/dnspod"
	"github.com/cloudrec/tencent/collector/mariadb"
	"github.com/cloudrec/tencent/collector/postgres"
	"github.com/cloudrec/tencent/collector/sqlserver"
	"github.com/cloudrec/tencent/collector/vpc"
)

func GetPlatformConfig() *schema.Platform {

	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.TencentCloud),
		Resources: []schema.Resource{
			clb.GetCLBResource(),
			cvm.GetInstanceResource(),
			vpc.GetGatewayResource(),
			vpc.GetSecurityGroupResource(),
			cdb.GetDBInstanceResource(),
			mariadb.GetMariaDBResource(),
			postgres.GetPostgresResource(),
			sqlserver.GetDBInstanceResource(),
			cam.GetUserResource(),
			cfs.GetFileSystemResource(),
			cos.GetBucketResource(),
			dnspod.GetDNSPodResource(),
		},
		Service: &collector.Services{},
		DefaultRegions: []string{
			"ap-bangkok",
			"ap-beijing",
			"ap-chengdu",
			"ap-chongqing",
			"ap-guangzhou",
			"ap-hongkong",
			"ap-jakarta",
			"ap-mumbai",
			"ap-nanjing",
			"ap-seoul",
			"ap-shanghai",
			"ap-shanghai-fsi",
			"ap-shenzhen-fsi",
			"ap-singapore",
			"ap-tokyo",
			"eu-frankfurt",
			"na-ashburn",
			"na-siliconvalley",
			"sa-saopaulo",
			"ap-beijing-fsi",
		},
	})

}
