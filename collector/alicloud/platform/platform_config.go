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
	"github.com/cloudrec/alicloud/collector"
	"github.com/cloudrec/alicloud/collector/ack"
	"github.com/cloudrec/alicloud/collector/acr"
	"github.com/cloudrec/alicloud/collector/actiontrail"
	"github.com/cloudrec/alicloud/collector/apig"
	"github.com/cloudrec/alicloud/collector/arms"
	"github.com/cloudrec/alicloud/collector/cas"
	"github.com/cloudrec/alicloud/collector/cdn"
	"github.com/cloudrec/alicloud/collector/cen"
	"github.com/cloudrec/alicloud/collector/cloudapi"
	"github.com/cloudrec/alicloud/collector/cloudcenter"
	"github.com/cloudrec/alicloud/collector/cloudfw"
	"github.com/cloudrec/alicloud/collector/cloudstoragegateway"
	"github.com/cloudrec/alicloud/collector/db/AnalyticDB/adbmysql"
	"github.com/cloudrec/alicloud/collector/db/AnalyticDB/adbpostgresql"
	"github.com/cloudrec/alicloud/collector/db/clickhouse"
	"github.com/cloudrec/alicloud/collector/db/hbase"
	"github.com/cloudrec/alicloud/collector/db/mongodb"
	"github.com/cloudrec/alicloud/collector/db/oceanbase"
	"github.com/cloudrec/alicloud/collector/db/polardb"
	"github.com/cloudrec/alicloud/collector/db/rds"
	"github.com/cloudrec/alicloud/collector/db/selectdb"
	"github.com/cloudrec/alicloud/collector/dcdn"
	"github.com/cloudrec/alicloud/collector/ddos"
	"github.com/cloudrec/alicloud/collector/dms"
	"github.com/cloudrec/alicloud/collector/dns"
	"github.com/cloudrec/alicloud/collector/dts"
	"github.com/cloudrec/alicloud/collector/eci"
	"github.com/cloudrec/alicloud/collector/ecp"
	"github.com/cloudrec/alicloud/collector/ecs"
	"github.com/cloudrec/alicloud/collector/eflo"
	"github.com/cloudrec/alicloud/collector/elasticsearch"
	"github.com/cloudrec/alicloud/collector/ens"
	"github.com/cloudrec/alicloud/collector/ess"
	"github.com/cloudrec/alicloud/collector/fc"
	"github.com/cloudrec/alicloud/collector/ga"
	"github.com/cloudrec/alicloud/collector/hitsdb"
	"github.com/cloudrec/alicloud/collector/ims"
	"github.com/cloudrec/alicloud/collector/kafka"
	"github.com/cloudrec/alicloud/collector/kms"
	"github.com/cloudrec/alicloud/collector/live"
	"github.com/cloudrec/alicloud/collector/loadbalance/alb"
	"github.com/cloudrec/alicloud/collector/loadbalance/nlb"
	"github.com/cloudrec/alicloud/collector/loadbalance/slb"
	"github.com/cloudrec/alicloud/collector/maxcompute"
	"github.com/cloudrec/alicloud/collector/mse"
	"github.com/cloudrec/alicloud/collector/nas"
	"github.com/cloudrec/alicloud/collector/ons"
	"github.com/cloudrec/alicloud/collector/oss"
	"github.com/cloudrec/alicloud/collector/pl"
	"github.com/cloudrec/alicloud/collector/ram"
	"github.com/cloudrec/alicloud/collector/redis"
	"github.com/cloudrec/alicloud/collector/resourcecenter"
	"github.com/cloudrec/alicloud/collector/rocketmq"
	"github.com/cloudrec/alicloud/collector/sls"
	"github.com/cloudrec/alicloud/collector/sms"
	"github.com/cloudrec/alicloud/collector/swas"
	"github.com/cloudrec/alicloud/collector/tablestore"
	"github.com/cloudrec/alicloud/collector/test"
	"github.com/cloudrec/alicloud/collector/vod"
	"github.com/cloudrec/alicloud/collector/vpc"
	"github.com/cloudrec/alicloud/collector/vpc/eip"
	"github.com/cloudrec/alicloud/collector/vpc/nat"
	"github.com/cloudrec/alicloud/collector/waf"
	"github.com/cloudrec/alicloud/collector/yundun"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
)

func GetPlatformConfig() *schema.Platform {
	// all region list from https://next.api.aliyun.com/product/Ecs
	alicloudRegions := []string{
		"cn-hangzhou",    //华东 1（杭州）
		"cn-qingdao",     //华北 1（青岛）
		"cn-beijing",     //华北 2（北京）
		"cn-zhangjiakou", //华北 3（张家口）
		"cn-huhehaote",   //华北 5（呼和浩特）
		"cn-wulanchabu",  //华北6（乌兰察布）
		"cn-shanghai",    //华东 2（上海）
		"cn-nanjing",     //华东 5（南京）
		"cn-shenzhen",    //华南 1（深圳）
		"cn-heyuan",      //华南2（河源）
		"cn-guangzhou",   //华南3（广州）
		"cn-chengdu",     //西南1（成都）
		"cn-hongkong",    //中国香港（香港）
		"ap-northeast-1", //亚太东北 1 (东京)
		"ap-southeast-1", //亚太东南 1 (新加坡)
		//"ap-southeast-2", //亚太东南 2 (悉尼) 已关停
		"ap-southeast-3", //亚太东南 3 (吉隆坡)
		"ap-southeast-5", //亚太东南 5 (雅加达)
		"us-east-1",      //美国东部 1 (弗吉尼亚)
		"us-west-1",      //美国西部 1 (硅谷)
		"eu-west-1",      //英国 (伦敦)
		"me-east-1",      //中东东部 1 (迪拜)
		"eu-central-1",   //欧洲中部 1 (法兰克福)
		"ap-northeast-2", //韩国 (首尔)
		"ap-southeast-6", //菲律宾 (马尼拉)
		"ap-southeast-7", //泰国 (曼谷)
		"me-central-1",   //中东中部 1 (利雅得)
		"cn-fuzhou",      //华东 6 (福州)
		//"ap-south-1",            //印度（孟买）已关停
		"cn-beijing-finance-1",  //华北2 金融云（邀测）
		"cn-hangzhou-finance",   //华东1 金融云
		"cn-shanghai-finance-1", //华东2 金融云
		"cn-shenzhen-finance-1", //华南1 金融云
		//"cn-zhengzhou-jva",      // 郑州（联通合营） 暂不启用
		//"cn-heyuan-acdr-1",      //河源专属云汽车合规 暂不启用
		//"cn-wuhan-lr",           // 华中1（武汉-本地地域）暂不启用
	}

	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.AlibabaCloud),
		Resources: []schema.Resource{
			resourcecenter.GeCloudCenterResource(),
			ddos.GetDDoSBGPResource(),
			cloudfw.GetCloudFWConfigResource(),
			cloudcenter.GetSasConfigResource(),
			cloudcenter.GetCloudCenterResource(),
			cloudstoragegateway.GetCloudStorageGatewayResource(),
			cloudstoragegateway.GetCloudStorageGatewayStorageBundleResource(),
			elasticsearch.GetResource(),
			elasticsearch.GetLogstashResource(),
			arms.GetTraceAppResource(),
			arms.GetGrafanaWorkspaceResource(),
			arms.GetARMSPrometheusResource(),
			ecs.GetInstanceResource(),
			ecs.GetSecurityGroupData(),
			ecs.GetImagesResource(),
			ecs.GetSnapshotsResource(),
			vpc.GetVPCResource(),
			nat.GetNatResource(),
			oss.GetBucketResource(),
			slb.GetSLBResource(),
			nlb.GetNLBResource(),
			alb.GetALBResource(),
			ram.GetRAMUserResource(),
			ram.GetRAMRoleResource(),
			//ram.GetGroupResource(),
			ims.GetAccountResource(),
			actiontrail.GetActionTrailResource(),
			cas.GetCERTResource(),
			cdn.GetCDNDomainResource(),
			waf.GetWAFResource(),
			eip.GetEIPResource(),
			redis.GeRedisResource(),
			maxcompute.GetMaxComputeResource(),
			cloudfw.GetCloudFWResource(),
			cloudfw.GetCloudFWConfigResource(),
			adbmysql.GetAnalyticDBMySQLResource(),
			adbpostgresql.GetAnalyticDBPostgreSQLResource(),
			hbase.GetHbaseResource(),
			clickhouse.GetClickHouseResource(),
			kafka.GetKafkaResource(),
			selectdb.GetSelectDBResource(),
			rds.GetRDSResource(),
			mongodb.GetMongoDBResource(),
			oceanbase.GetOceanbaseResource(),
			polardb.GetPolarDBResource(),
			acr.GetCRResource(),
			sls.GetSLSResource(),
			cen.GetCENResource(),
			pl.GetPrivateLinkResource(),
			dns.GetDNSResource(),
			rocketmq.GetRocketMQResource(),
			dms.GetDMSResource(),
			fc.GetFCResource(),
			ess.GetESSResource(),
			nas.GetNASResource(),
			dns.GetDomainRRResource(),
			hitsdb.GetLindormResource(),
			ens.GetInstanceResource(),
			ens.GetEipAddressesResource(),
			ens.GetLoadBalancerResource(),
			ens.GetNetworkResource(),
			ens.GetNatGatewayResource(),
			//cloudapi.GetCloudAPIResource(),
			cloudapi.GetAPIGatewayResource(),
			cloudapi.GetAPIGatewayAppResource(),
			kms.GetKMSResource(),
			ack.GetClusterResource(),
			mse.GetMSEResource(),
			tablestore.GetTablestoreResource(),
			yundun.GetResource(),
			yundun.GetBastionhostResource(),
			apig.GetDomainData(),
			dts.GetDTSInstanceResource(),
			eci.GetECIContainerGroupResource(),
			eci.GetECIImageCacheResource(),
			ecp.GetInstanceResource(),
			swas.GetInstanceResource(),
			vpc.GetVPNConnectionResource(),
			ga.GetAcceleratorResource(),
			eflo.GetNodeResource(),
			ons.GetInstanceResource(),
			dcdn.GetDCDNDomainResource(),
			dcdn.GetDCDNIpaDomainResource(),
			vod.GetVODDomainResource(),
			sms.GetSMSTemplateResource(),
			live.GetLiveDomainResource(),
		},

		Service:        &collector.Services{},
		DefaultRegions: alicloudRegions,
	})
}

func GetPlatformConfigTest() *schema.Platform {
	alicloudRegions := []string{
		"cn-beijing", "cn-beijing-finance-1"}

	testAccount1 := schema.CloudAccount{
		CloudAccountId: "test111111",
		Platform:       string(constant.AlibabaCloud),
		CommonCloudAccountAuthParam: schema.CommonCloudAccountAuthParam{
			AK: "xxx",
			SK: "xxx",
		},
	}

	testAccount2 := schema.CloudAccount{
		CloudAccountId: "test222222",
		Platform:       string(constant.AlibabaCloud),
		CommonCloudAccountAuthParam: schema.CommonCloudAccountAuthParam{
			AK: "xxx",
			SK: "xxx",
		},
	}

	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.AlibabaCloud),
		Resources: []schema.Resource{
			test.TestBlockResource(),
			test.TestAutoExitResource(),
			test.TestTimeOutResource(),
			test.TestBlockResource2(),
		},

		Service:              &collector.Services{},
		DefaultRegions:       alicloudRegions,
		DefaultCloudAccounts: []schema.CloudAccount{testAccount1, testAccount2},
	})
}
