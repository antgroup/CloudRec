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
	"github.com/cloudrec/ksyun/collector"
	"github.com/cloudrec/ksyun/collector/bigdata/kes"
	"github.com/cloudrec/ksyun/collector/compute/epc"
	"github.com/cloudrec/ksyun/collector/compute/kec"
	"github.com/cloudrec/ksyun/collector/container/kce"
	"github.com/cloudrec/ksyun/collector/container/kcrs"
	"github.com/cloudrec/ksyun/collector/database/kcs"
	"github.com/cloudrec/ksyun/collector/database/krds"
	"github.com/cloudrec/ksyun/collector/database/postgresql"
	"github.com/cloudrec/ksyun/collector/database/sqlserver"
	"github.com/cloudrec/ksyun/collector/identity/iam"
	"github.com/cloudrec/ksyun/collector/log/klog"
	"github.com/cloudrec/ksyun/collector/middleware/rabbitmq"
	"github.com/cloudrec/ksyun/collector/net/cdn"
	"github.com/cloudrec/ksyun/collector/net/eip"
	"github.com/cloudrec/ksyun/collector/net/loadbalance/alb"
	"github.com/cloudrec/ksyun/collector/net/loadbalance/slb"
	"github.com/cloudrec/ksyun/collector/net/vpc"
	"github.com/cloudrec/ksyun/collector/net/vpc/nat"
	"github.com/cloudrec/ksyun/collector/net/vpc/securitygroup"
	"github.com/cloudrec/ksyun/collector/security/kcm"
	"github.com/cloudrec/ksyun/collector/security/knad"
	"github.com/cloudrec/ksyun/collector/security/waf"
	"github.com/cloudrec/ksyun/collector/store/kfs"
	"github.com/cloudrec/ksyun/collector/store/ks3"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
)

func GetPlatformConfig() *schema.Platform {

	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.KingsoftCloud),
		Resources: []schema.Resource{
			vpc.GetVPCResource(),
			securitygroup.GetSecurityGroupResource(),
			nat.GetNATResource(),
			eip.GetEIPResource(),
			epc.GetEPCResource(),
			kec.GetKECResource(),
			slb.GetSLBResource(),
			alb.GetALBResource(),
			kce.GetKCEResource(),
			kcrs.GetKCRSResource(),
			krds.GetKRDSResource(),
			kcs.GetKCSResource(),
			sqlserver.GetSQLServerResource(),
			postgresql.GetPostgreSQLResource(),
			klog.GetKLOGResource(),
			ks3.GetKS3Resource(),
			cdn.GetCDNResource(),
			iam.GetIAMUserResource(),
			iam.GetIAMRoleResource(),
			rabbitmq.GetRabbitMQResource(),
			kes.GetKESResource(),
			kfs.GetKFSResource(),
			kcm.GetKCMResource(),
			waf.GetWAFResource(),
			knad.GetKNADResource(),
		},
		Service: &collector.Services{},
		DefaultRegions: []string{
			"cn-beijing-6",    // 华北1（北京）
			"cn-shanghai-2",   // 华东1（上海）
			"cn-guangzhou-1",  // 华南1（广州）
			"cn-central-1",    // 华中1（武汉）
			"cn-hongkong-2",   // 香港
			"ap-singapore-1",  // 新加坡
			"eu-east-1",       // 俄罗斯（莫斯科）
			"cn-taipei-1",     // 台北
			"cn-shanghai-fin", // 华东金融1（上海）
			"cn-beijing-fin",  // 华北金融1（北京）
			"cn-southwest-1",  // 西南1（重庆）
			"cn-northwest-1",  // 西北1（庆阳）
			"cn-northwest-2",  // 西北2区（庆阳）
			"cn-northwest-3",  // 西北3区（宁夏）
			"cn-northwest-4",  // 西北4（海东）
			"cn-northwest-5",  // 西北5（克拉玛依)
			"cn-north-vip1",   // 华北专属1区（天津-小米）
			"cn-north-1-gov",  // 华北政务1（北京）
			"cn-ningbo-1",     // 华东2（宁波）
			"cn-qingdao-1",    // 自用（青岛）
		},
	})

}
