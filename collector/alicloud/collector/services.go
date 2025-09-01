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
	"net/http"
	"strings"
	"time"

	actiontrail20200706 "github.com/alibabacloud-go/actiontrail-20200706/v3/client"
	adb20190315 "github.com/alibabacloud-go/adb-20190315/v4/client"
	alb20200616 "github.com/alibabacloud-go/alb-20200616/v2/client"
	alidns20150109 "github.com/alibabacloud-go/alidns-20150109/v4/client"
	apig20240327 "github.com/alibabacloud-go/apig-20240327/v3/client"
	arms20190808 "github.com/alibabacloud-go/arms-20190808/v8/client"
	cas20200407 "github.com/alibabacloud-go/cas-20200407/v3/client"
	cbn20170912 "github.com/alibabacloud-go/cbn-20170912/v2/client"
	cloudapi20160714 "github.com/alibabacloud-go/cloudapi-20160714/v5/client"
	cloudfw20171207 "github.com/alibabacloud-go/cloudfw-20171207/v7/client"
	cr20181201 "github.com/alibabacloud-go/cr-20181201/v2/client"
	cs20151215 "github.com/alibabacloud-go/cs-20151215/v5/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ddoscoo20200101 "github.com/alibabacloud-go/ddoscoo-20200101/v3/client"
	dds20151201 "github.com/alibabacloud-go/dds-20151201/v8/client"
	dms_enterprise20181101 "github.com/alibabacloud-go/dms-enterprise-20181101/client"
	eds_aic20230930 "github.com/alibabacloud-go/eds-aic-20230930/v4/client"
	elasticsearch20170613 "github.com/alibabacloud-go/elasticsearch-20170613/v3/client"
	ess20220222 "github.com/alibabacloud-go/ess-20220222/v2/client"
	fc20230330 "github.com/alibabacloud-go/fc-20230330/v4/client"
	gpdb20160503 "github.com/alibabacloud-go/gpdb-20160503/v3/client"
	hitsdb20200615 "github.com/alibabacloud-go/hitsdb-20200615/v5/client"
	ims20190815 "github.com/alibabacloud-go/ims-20190815/v4/client"
	kms20160120 "github.com/alibabacloud-go/kms-20160120/v3/client"
	maxcompute20220104 "github.com/alibabacloud-go/maxcompute-20220104/client"
	mse20190531 "github.com/alibabacloud-go/mse-20190531/v5/client"
	nas "github.com/alibabacloud-go/nas-20170626/v3/client"
	nlb20220430 "github.com/alibabacloud-go/nlb-20220430/v3/client"
	oceanbasepro20190901 "github.com/alibabacloud-go/oceanbasepro-20190901/v8/client"
	polardb20170801 "github.com/alibabacloud-go/polardb-20170801/v6/client"
	privatelink20200415 "github.com/alibabacloud-go/privatelink-20200415/v5/client"
	r_kvstore20150101 "github.com/alibabacloud-go/r-kvstore-20150101/v5/client"
	rds20140815 "github.com/alibabacloud-go/rds-20140815/v6/client"
	resourcecenter20221201 "github.com/alibabacloud-go/resourcecenter-20221201/client"
	rocketmq20220801 "github.com/alibabacloud-go/rocketmq-20220801/client"
	sas20181203 "github.com/alibabacloud-go/sas-20181203/v3/client"
	selectdb20230522 "github.com/alibabacloud-go/selectdb-20230522/v3/client"
	slb20140515 "github.com/alibabacloud-go/slb-20140515/v4/client"
	sls20201230 "github.com/alibabacloud-go/sls-20201230/v6/client"
	swas_open20200601 "github.com/alibabacloud-go/swas-open-20200601/v3/client"
	tablestore20201209 "github.com/alibabacloud-go/tablestore-20201209/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	waf_openapi20211001 "github.com/alibabacloud-go/waf-openapi-20211001/v4/client"
	yundun_bastionhost20191209 "github.com/alibabacloud-go/yundun-bastionhost-20191209/v2/client"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/actiontrail"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alikafka"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cdn"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/clickhouse"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dcdn"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dts"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eci"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eflo"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eflo-controller"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ens"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ga"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/hbase"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/live"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ons"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sgw"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vod"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	ossCredentials "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

var RuntimeObject = new(util.RuntimeOptions)
var conf = sdk.NewConfig()

func init() {
	conf.WithAutoRetry(true).WithTimeout(5 * time.Second).WithMaxRetryTime(1)
	var transport = &http.Transport{
		IdleConnTimeout:       3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	conf.HttpTransport = transport
	RuntimeObject.SetAutoretry(true)
	RuntimeObject.SetMaxAttempts(1)
}

func openapiConfig(region string, accessKeyId, accessKeySecret string) *openapi.Config {
	config := &openapi.Config{
		// Required, make sure the environment variable ALIBABA_CLOUD_ACCESS_KEY_ID is set
		AccessKeyId: tea.String(accessKeyId),
		// Required, make sure the environment variable ALIBABA_CLOUD_ACCESS_KEY_SECRET is set
		AccessKeySecret: tea.String(accessKeySecret),
		RegionId:        tea.String(region),
	}

	// connect time 10s
	config.SetConnectTimeout(10000)
	config.SetReadTimeout(20000)
	config.SetMaxIdleConns(100)

	return config
}

// Services needs to be implemented on every cloud platform
type Services struct {
	CloudAccountId  string
	Config          *openapi.Config
	ECS             *ecs.Client
	VPC             *vpc.Client
	OSS             *oss.Client
	SLB             *slb20140515.Client
	NLB             *nlb20220430.Client
	ALB             *alb20200616.Client
	RAM             *ram.Client
	IMS             *ims20190815.Client
	Actiontrail     *actiontrail.Client
	Alikafka        *alikafka.Client
	Sas             *sas20181203.Client
	CDN             *cdn.Client
	WAF             *waf_openapi20211001.Client
	Clickhouse      *clickhouse.Client
	Redis           *r_kvstore20150101.Client
	Selectdb        *selectdb20230522.Client
	Oceanbasepro    *oceanbasepro20190901.Client
	Elasticsearch   *elasticsearch20170613.Client
	Cloudfw         *cloudfw20171207.Client
	MongoDB         *dds20151201.Client
	RDS             *rds20140815.Client
	Polardb         *polardb20170801.Client
	AnalyticDBMySQL *adb20190315.Client
	CAS             *cas20200407.Client
	AdbPostgreSQL   *gpdb20160503.Client
	Maxcompute      *maxcompute20220104.Client
	Hbase           *hbase.Client
	ACK             *cs20151215.Client
	ACR             *cr20181201.Client
	SLS             *sls20201230.Client
	NAS             *nas.Client
	ESS             *ess20220222.Client
	FC              *fc20230330.Client
	Tablestore      *tablestore20201209.Client
	DMS             *dms_enterprise20181101.Client
	Privatelink     *privatelink20200415.Client
	DNS             *alidns20150109.Client
	RocketMQ        *rocketmq20220801.Client
	CEN             *cbn20170912.Client
	CloudAPI        *cloudapi20160714.Client
	ARMS            *arms20190808.Client
	MSE             *mse20190531.Client
	KMS             *kms20160120.Client
	HITSDB          *hitsdb20200615.Client
	ENS             *ens.Client
	YUNDUN          *yundun_bastionhost20191209.Client
	DDoS            *ddoscoo20200101.Client
	APIG            *apig20240327.Client
	ResourceCenter  *resourcecenter20221201.Client
	DTS             *dts.Client
	Dysmsapi        *dysmsapi.Client
	ECI             *eci.Client
	ECP             *eds_aic20230930.Client
	Eflo            *eflo.Client
	EfloController  *eflo_controller.Client
	SWAS            *swas_open20200601.Client
	Ons             *ons.Client
	GA              *ga.Client
	DCDN            *dcdn.Client
	VOD             *vod.Client
	SGW             *sgw.Client
	Live            *live.Client
}

// Clone creates a new instance of Services with copied configuration
func (s *Services) Clone() schema.ServiceInterface {
	return &Services{}
}

func (s *Services) InitServices(cloudAccountParam schema.CloudAccountParam) (err error) {
	param := cloudAccountParam.CommonCloudAccountParam
	s.CloudAccountId = cloudAccountParam.CloudAccountId
	s.Config = openapiConfig(param.Region, param.AK, param.SK)
	s.Config.ConnectTimeout = tea.Int(10000)
	s.Config.ReadTimeout = tea.Int(20000)

	if cloudAccountParam.ProxyConfig != "" {
		s.Config.HttpProxy = tea.String(cloudAccountParam.ProxyConfig)
		s.Config.HttpsProxy = tea.String(cloudAccountParam.ProxyConfig)
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, constant.CloudAccountId, cloudAccountParam.CloudAccountId)
	ctx = context.WithValue(ctx, constant.RegionId, param.Region)
	ctx = context.WithValue(ctx, constant.ResourceType, cloudAccountParam.ResourceType)
	switch cloudAccountParam.ResourceType {

	case ECS, SecurityGroup, ECSImage, ECSSnapshot:
		s.ECS, err = ecs.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ecs client failed", zap.Error(err))
		}
		s.ECS.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.ECS.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case VPC, NAT, EIP, VpnConnection:
		s.VPC, err = vpc.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init vpc client failed", zap.Error(err))
		}
		s.VPC.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.VPC.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case OSS:
		cfg := oss.LoadDefaultConfig().
			WithCredentialsProvider(ossCredentials.NewStaticCredentialsProvider(param.AK, param.SK)).
			WithRegion(param.Region)
		// A judgment must be made, otherwise it will be overwritten, affecting the execution result
		if cloudAccountParam.ProxyConfig != "" {
			cfg.WithProxyHost(cloudAccountParam.ProxyConfig)
		}
		s.OSS = oss.NewClient(cfg)
	case SLB:
		s.SLB, err = createSlbClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init slb client failed", zap.Error(err))
		}
		s.VPC, err = createVPCClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init vpc client failed", zap.Error(err))
		}
	case RAMUser, RAMRole, RMAGroup:
		s.RAM, err = ram.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ram client failed", zap.Error(err))
		}
		s.RAM.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.RAM.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case Account:
		s.IMS, err = createImsClient("cn-hangzhou", s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ims client failed", zap.Error(err))
		}
	case ActionTrail:
		s.Actiontrail, err = actiontrail.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init actiontrail client failed", zap.Error(err))
		}
		s.Actiontrail.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.Actiontrail.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case Kafka:
		s.Alikafka, err = alikafka.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init alikafka client failed", zap.Error(err))
		}
		s.Alikafka.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.Alikafka.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case Sas, SasConfig:
		s.Sas, err = createSasClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init sas client failed", zap.Error(err))
		}
	case CDN:
		s.CDN, err = cdn.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init cdn client failed", zap.Error(err))
		}
		s.CDN.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.CDN.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case WAF:
		s.WAF, err = createWafClient(s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init waf client failed", zap.Error(err))
		}
	case NLB:
		s.NLB, err = createNlbClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init nlb client failed", zap.Error(err))
		}
	case ALB:
		s.ALB, err = createALbClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init alb client failed", zap.Error(err))
		}
	case ClickHouse:
		s.Clickhouse, err = clickhouse.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init clickhouse client failed", zap.Error(err))
		}
		s.Clickhouse.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.Clickhouse.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case Redis:
		s.Redis, err = createRedisClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init redis client failed", zap.Error(err))
		}
	case Oceanbase:
		s.Oceanbasepro, err = createOceanBaseClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init oceanbasepro client failed", zap.Error(err))
		}
	case Elasticsearch:
		s.Elasticsearch, err = createElasticsearchClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init elasticsearch client failed", zap.Error(err))
		}
	case Cloudfw, CloudfwConfig:
		s.Cloudfw, err = createCloudfwClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init cloudfw client failed", zap.Error(err))
		}
	case MongoDB:
		s.MongoDB, err = createMongoDBClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init mongoDB client failed", zap.Error(err))
		}
	case RDS:
		s.RDS, err = createRDSClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init rds client failed", zap.Error(err))
		}
	case PolarDB:
		s.Polardb, err = createPolarDBClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init polardb client failed", zap.Error(err))
		}
	case AnalyticDBMySQL:
		s.AnalyticDBMySQL, err = createAdbMysqlClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init analyticDBMySQL client failed", zap.Error(err))
		}
	case CERT:
		s.CAS, err = createCasClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init cas client failed", zap.Error(err))
		}
	case AnalyticDBPostgreSQL:
		s.AdbPostgreSQL, err = CreateAdbPostgreSQLClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init adbPostgreSQL client failed", zap.Error(err))
		}
	case MAX_COMPUTE:
		s.Maxcompute, err = createMaxComputeClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init maxcompute client failed", zap.Error(err))
		}
	case Hbase:
		s.Hbase, err = hbase.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init hbase client failed", zap.Error(err))
		}
		s.Hbase.SetHttpProxy(cloudAccountParam.ProxyConfig)
		s.Hbase.SetHttpsProxy(cloudAccountParam.ProxyConfig)
	case SelectDB:
		s.Selectdb, err = createSelectDBClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init selectdb client failed", zap.Error(err))
		}
	case ACKCluster:
		s.ACK, err = createK8sClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init kubernetes client failed", zap.Error(err))
		}
	case ACR:
		s.ACR, err = createAcrClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init acr client failed", zap.Error(err))
		}
	case SLS:
		s.SLS, err = createSLSClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init sls client failed", zap.Error(err))
		}
	case NAS:
		s.NAS, err = createNASClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init nas client failed", zap.Error(err))
		}
	case ESS:
		s.ESS, err = createESSClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ess client failed", zap.Error(err))
		}
	case FC:
		s.FC, err = createFCClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init fc client failed", zap.Error(err))
		}
	case Tablestore:
		s.Tablestore, err = CreateTablestoreClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init tablestore client failed", zap.Error(err))
		}
	case DMS:
		s.DMS, err = createDMSClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init dms client failed", zap.Error(err))
		}
	case PrivateLink:
		s.Privatelink, err = createPrivateLinkClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init privatelink client failed", zap.Error(err))
		}
	case DNS, DomainRR:
		s.DNS, err = createDNSClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init dns client failed", zap.Error(err))
		}
	case RocketMQ:
		s.RocketMQ, err = createRocketMQClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init rocketMQ client failed", zap.Error(err))
		}
	case CEN:
		s.CEN, err = createCENClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init cen client failed", zap.Error(err))
		}
	case CloudAPI, APIGateway, APIGatewayApp:
		s.CloudAPI, err = CreateCloudAPIClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init cloudAPI client failed", zap.Error(err))
		}
	case TraceApp, GrafanaWorkspace, ARMSPrometheus:
		s.ARMS, err = CreateARMSClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init arms client failed", zap.Error(err))
		}
	case MSE:
		s.MSE, err = CreateMSEClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init mse client failed", zap.Error(err))
		}
	case KMS:
		s.KMS, err = CreateKMSClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init kms client failed", zap.Error(err))
		}
	case Lindorm:
		s.HITSDB, err = CreateHitsdbClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init lindorm client failed", zap.Error(err))
		}
	case ENSInstance, ENSNetwork, ENSEip, ENSNatGateway, ENSLoadBalancer:
		s.ENS, err = createENSClient(s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ens client failed", zap.Error(err))
		}
	case Yundun, Bastionhost:
		s.YUNDUN, err = createYundunClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init yundun client failed", zap.Error(err))
		}
	case DdosCoo:
		s.DDoS, err = createDDoSBGPClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ddos client failed", zap.Error(err))
		}
	case APIG:
		s.APIG, err = createAPIGClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init apig client failed", zap.Error(err))
		}
	case ResourceCenter:
		s.ResourceCenter, err = createResourceClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init resourcecenter client failed", zap.Error(err))
		}
	case DTSInstance:
		s.DTS, err = dts.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init dts client failed", zap.Error(err))
		}
	case ECIContainerGroup, ECIImageCache:
		s.ECI, err = eci.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init eci client failed", zap.Error(err))
		}
	case SWAS:
		s.SWAS, err = createSWASClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init swas client failed", zap.Error(err))
		}
	case ECPInstance:
		s.ECP, err = createECPClient(param.Region, s.Config)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ecp client failed", zap.Error(err))
		}
	case ONS_INSTANCE:
		s.Ons, err = ons.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ons client failed", zap.Error(err))
		}
	case EfloNode:
		s.EfloController, err = eflo_controller.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init eflo controller client failed", zap.Error(err))
		}
	case GAAccelerator:
		s.GA, err = ga.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init ga client failed", zap.Error(err))
		}
	case DCDNDomain, DCDNIpaDomain:
		s.DCDN, err = dcdn.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init dcdn client failed", zap.Error(err))
		}
	case LiveDomain:
		s.Live, err = live.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init live client failed", zap.Error(err))
		}
	case VODDomain:
		s.VOD, err = vod.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init vod client failed", zap.Error(err))
		}
	case SMSTemplate:
		s.Dysmsapi, err = dysmsapi.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init dysmsapi client failed", zap.Error(err))
		}
	case CloudStorageGateway, CloudStorageGatewayStorageBundle:
		s.SGW, err = sgw.NewClientWithAccessKey(param.Region, param.AK, param.SK)
		if err != nil {
			log.CtxLogger(ctx).Warn("init sgw client failed", zap.Error(err))
		}
	}

	return nil
}

func createSWASClient(region string, config *openapi.Config) (client *swas_open20200601.Client, err error) {
	config.Endpoint = tea.String("swas." + region + ".aliyuncs.com")
	client, err = swas_open20200601.NewClient(config)
	return client, err
}

func createVPCClient(region string, config *openapi.Config) (client *vpc.Client, err error) {
	client, err = vpc.NewClientWithAccessKey(region, *config.AccessKeyId, *config.AccessKeySecret)
	return client, err
}

func createENSClient(config *openapi.Config) (client *ens.Client, err error) {
	config.Endpoint = tea.String("ens.aliyuncs.com")
	client, err = ens.NewClientWithAccessKey("cn-hangzhou", *config.AccessKeyId, *config.AccessKeySecret)
	return client, err
}

func CreateHitsdbClient(region string, config *openapi.Config) (client *hitsdb20200615.Client, err error) {
	// https://api.aliyun.com/product/hitsdb
	config.Endpoint = tea.String("hitsdb." + region + ".aliyuncs.com")
	client, err = hitsdb20200615.NewClient(config)
	return client, err
}

func createSlbClient(region string, config *openapi.Config) (client *slb20140515.Client, err error) {
	config.Endpoint = tea.String("slb." + region + ".aliyuncs.com")
	client, err = slb20140515.NewClient(config)
	client.RegionId = tea.String(region)

	return client, err
}

func createSasClient(regionId string, config *openapi.Config) (*sas20181203.Client, error) {
	cli, err := sas20181203.NewClient(config)
	// only support cn-shanghai and ap-southeast-1
	if strings.HasPrefix(regionId, "cn-") {
		config.Endpoint = tea.String("tds.cn-shanghai.aliyuncs.com")
	} else {
		config.Endpoint = tea.String("tds.ap-southeast-1.aliyuncs.com")
	}
	if err != nil {
		return nil, err
	}
	return cli, nil
}

func createWafClient(config *openapi.Config) (_result *waf_openapi20211001.Client, _err error) {
	_result = &waf_openapi20211001.Client{}
	_result, _err = waf_openapi20211001.NewClient(config)
	return _result, _err
}

func createNlbClient(region string, config *openapi.Config) (_result *nlb20220430.Client, _err error) {
	config.Endpoint = tea.String("nlb." + region + ".aliyuncs.com")
	_result = &nlb20220430.Client{}
	_result, _err = nlb20220430.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createALbClient(region string, config *openapi.Config) (_result *alb20200616.Client, _err error) {
	config.Endpoint = tea.String("alb." + region + ".aliyuncs.com")
	_result = &alb20200616.Client{}
	_result, _err = alb20200616.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createSelectDBClient(region string, config *openapi.Config) (_result *selectdb20230522.Client, _err error) {
	config.Endpoint = tea.String("selectdb." + region + ".aliyuncs.com")
	_result = &selectdb20230522.Client{}
	_result, _err = selectdb20230522.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createRedisClient(region string, config *openapi.Config) (_result *r_kvstore20150101.Client, _err error) {
	config.Endpoint = tea.String("r-kvstore.aliyuncs.com")
	_result = &r_kvstore20150101.Client{}
	_result, _err = r_kvstore20150101.NewClient(config)
	if _err != nil {
		return
	}

	describeRegionsRequest := &r_kvstore20150101.DescribeRegionsRequest{}
	res, err := _result.DescribeRegionsWithOptions(describeRegionsRequest, RuntimeObject)
	if err != nil {
		return nil, err
	}
	for _, r := range res.Body.RegionIds.KVStoreRegion {
		if tea.StringValue(r.RegionId) == region {
			config.Endpoint = r.RegionEndpoint
			break
		}
	}

	_result, _err = r_kvstore20150101.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, nil
}

func createOceanBaseClient(region string, config *openapi.Config) (_result *oceanbasepro20190901.Client, _err error) {
	config.Endpoint = tea.String("oceanbasepro." + region + ".aliyuncs.com")
	_result = &oceanbasepro20190901.Client{}
	_result, _err = oceanbasepro20190901.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, nil
}

func createElasticsearchClient(region string, config *openapi.Config) (_result *elasticsearch20170613.Client, _err error) {
	config.Endpoint = tea.String("elasticsearch." + region + ".aliyuncs.com")
	_result = &elasticsearch20170613.Client{}
	_result, _err = elasticsearch20170613.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createCloudfwClient(region string, config *openapi.Config) (_result *cloudfw20171207.Client, _err error) {
	endponit := "cloudfw.aliyuncs.com"
	if region == "ap-southeast-1" {
		endponit = "cloudfw.ap-southeast-1.aliyuncs.com"
	}
	config.Endpoint = tea.String(endponit)
	_result = &cloudfw20171207.Client{}
	_result, _err = cloudfw20171207.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createYundunClient(region string, config *openapi.Config) (_result *yundun_bastionhost20191209.Client, _err error) {
	endPointMap := map[string]string{
		"cn-qingdao":            "yundun-bastionhost.aliyuncs.com",
		"cn-beijing":            "yundun-bastionhost.aliyuncs.com",
		"cn-zhangjiakou":        "bastionhost.cn-zhangjiakou.aliyuncs.com",
		"cn-huhehaote":          "bastionhost.cn-huhehaote.aliyuncs.com",
		"cn-hangzhou":           "yundun-bastionhost.aliyuncs.com",
		"ap-southeast-2":        "bastionhost.ap-southeast-2.aliyuncs.com",
		"ap-southeast-3":        "bastionhost.ap-southeast-3.aliyuncs.com",
		"ap-southeast-1":        "bastionhost.ap-southeast-1.aliyuncs.com",
		"ap-southeast-5":        "bastionhost.ap-southeast-5.aliyuncs.com",
		"cn-hongkong":           "bastionhost.cn-hongkong.aliyuncs.com",
		"eu-central-1":          "bastionhost.eu-central-1.aliyuncs.com",
		"us-east-1":             "bastionhost.us-east-1.aliyuncs.com",
		"us-west-1":             "bastionhost.us-west-1.aliyuncs.com",
		"eu-west-1":             "bastionhost.eu-west-1.aliyuncs.com",
		"me-east-1":             "yundun-bastionhost.aliyuncs.com",
		"ap-south-1":            "bastionhost.ap-south-1.aliyuncs.com",
		"cn-shanghai-finance-1": "yundun-bastionhost.aliyuncs.com",
		"cn-shenzhen-finance-1": "yundun-bastionhost.aliyuncs.com",
	}

	endpoint := endPointMap[region]
	if endpoint == "" {
		endpoint = "yundun-bastionhost.aliyuncs.com"
	}
	config.Endpoint = tea.String(endpoint)
	_result = &yundun_bastionhost20191209.Client{}
	_result, _err = yundun_bastionhost20191209.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createAPIGClient(region string, config *openapi.Config) (_result *apig20240327.Client, _err error) {
	config.Endpoint = tea.String("apig." + region + ".aliyuncs.com")
	_result = &apig20240327.Client{}
	_result, _err = apig20240327.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createMongoDBClient(region string, config *openapi.Config) (_result *dds20151201.Client, _err error) {
	config.Endpoint = tea.String("mongodb.aliyuncs.com")
	_result = &dds20151201.Client{}
	_result, _err = dds20151201.NewClient(config)
	if _err != nil {
		return
	}

	describeRegionsRequest := &dds20151201.DescribeRegionsRequest{
		RegionId: tea.String(region),
	}
	result, err := _result.DescribeRegions(describeRegionsRequest)
	if err != nil {
		return nil, err
	}
	for _, r := range result.Body.Regions.DdsRegion {
		if tea.StringValue(r.RegionId) == region {
			config.Endpoint = r.EndPoint
			break
		}
	}

	_result, _err = dds20151201.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createRDSClient(region string, config *openapi.Config) (_result *rds20140815.Client, _err error) {
	config.Endpoint = tea.String("rds.aliyuncs.com")
	_result = &rds20140815.Client{}
	_result, _err = rds20140815.NewClient(config)
	if _err != nil {
		return
	}
	describeRegionsRequest := &rds20140815.DescribeRegionsRequest{}
	result, err := _result.DescribeRegionsWithOptions(describeRegionsRequest, RuntimeObject)
	if err != nil {
		return nil, err
	}
	for _, r := range result.Body.Regions.RDSRegion {
		if tea.StringValue(r.RegionId) == region {
			config.Endpoint = r.RegionEndpoint
			break
		}
	}

	_result, _err = rds20140815.NewClient(config)
	_result.RegionId = tea.String(region)

	return _result, _err
}

func createPolarDBClient(region string, config *openapi.Config) (_result *polardb20170801.Client, _err error) {
	endPointMap := map[string]string{
		"cn-hangzhou":    "polardb.aliyuncs.com",
		"cn-zhangjiakou": "polardb.cn-zhangjiakou.aliyuncs.com",
		"cn-huhehaote":   "polardb.cn-huhehaote.aliyuncs.com",
		"ap-southeast-2": "polardb.ap-southeast-2.aliyuncs.com",
		"ap-southeast-6": "polardb.ap-southeast-6.aliyuncs.com",
		"ap-northeast-2": "polardb.ap-northeast-2.aliyuncs.com",
		"ap-southeast-3": "polardb.ap-southeast-3.aliyuncs.com",
		"ap-northeast-1": "polardb.ap-northeast-1.aliyuncs.com",
		"ap-southeast-7": "polardb.ap-southeast-7.aliyuncs.com",
		"cn-chengdu":     "polardb.cn-chengdu.aliyuncs.com",
		"ap-southeast-1": "polardb.ap-southeast-1.aliyuncs.com",
		"ap-southeast-5": "polardb.ap-southeast-5.aliyuncs.com",
		"eu-central-1":   "polardb.eu-central-1.aliyuncs.com",
		"us-east-1":      "polardb.us-east-1.aliyuncs.com",
		"us-west-1":      "polardb.us-west-1.aliyuncs.com",
		"eu-west-1":      "polardb.eu-west-1.aliyuncs.com",
		"me-east-1":      "polardb.me-east-1.aliyuncs.com",
		"ap-south-1":     "polardb.ap-south-1.aliyuncs.com",
	}

	endpoint := endPointMap[region]
	if endpoint == "" {
		endpoint = "polardb.aliyuncs.com"
	}
	config.Endpoint = tea.String(endpoint)
	_result = &polardb20170801.Client{}
	_result, _err = polardb20170801.NewClient(config)
	if _err != nil {
		return
	}

	_result.RegionId = config.RegionId
	return _result, _err
}

func createAdbMysqlClient(region string, config *openapi.Config) (_result *adb20190315.Client, _err error) {
	_result = &adb20190315.Client{}
	config.Endpoint = tea.String("adb.aliyuncs.com")
	_result, _err = adb20190315.NewClient(config)
	if _err != nil {
		return
	}
	describeRegionsRequest := &adb20190315.DescribeRegionsRequest{}
	result, err := _result.DescribeRegions(describeRegionsRequest)
	if err != nil {
		return nil, err
	}
	for _, r := range result.Body.Regions.Region {
		if tea.StringValue(r.RegionId) == region {
			config.Endpoint = r.RegionEndpoint
			break
		}
	}

	_result, _err = adb20190315.NewClient(config)
	_result.RegionId = config.RegionId
	return _result, _err
}

func CreateAdbPostgreSQLClient(region string, config *openapi.Config) (_result *gpdb20160503.Client, _err error) {
	endPointMap := map[string]string{
		"cn-beijing":            "gpdb.aliyuncs.com",
		"cn-zhangjiakou":        "gpdb.cn-zhangjiakou.aliyuncs.com",
		"cn-huhehaote":          "gpdb.cn-huhehaote.aliyuncs.com",
		"cn-hangzhou":           "gpdb.aliyuncs.com",
		"cn-shanghai":           "gpdb.aliyuncs.com",
		"cn-shenzhen":           "gpdb.aliyuncs.com",
		"ap-southeast-2":        "gpdb.ap-southeast-2.aliyuncs.com",
		"ap-northeast-2":        "gpdb.ap-northeast-2.aliyuncs.com",
		"ap-southeast-3":        "gpdb.ap-southeast-3.aliyuncs.com",
		"ap-northeast-1":        "gpdb.ap-northeast-1.aliyuncs.com",
		"ap-southeast-7":        "gpdb.ap-southeast-7.aliyuncs.com",
		"cn-chengdu":            "gpdb.cn-chengdu.aliyuncs.com",
		"ap-southeast-1":        "gpdb.aliyuncs.com",
		"ap-southeast-5":        "gpdb.ap-southeast-5.aliyuncs.com",
		"cn-hongkong":           "gpdb.aliyuncs.com",
		"eu-central-1":          "gpdb.eu-central-1.aliyuncs.com",
		"us-east-1":             "gpdb.us-east-1.aliyuncs.com",
		"us-west-1":             "gpdb.us-west-1.aliyuncs.com",
		"eu-west-1":             "gpdb.eu-west-1.aliyuncs.com",
		"me-east-1":             "gpdb.me-east-1.aliyuncs.com",
		"ap-south-1":            "gpdb.ap-south-1.aliyuncs.com",
		"cn-beijing-finance-1":  "gpdb.aliyuncs.com",
		"cn-hangzhou-finance":   "gpdb.aliyuncs.com",
		"cn-shanghai-finance-1": "gpdb.aliyuncs.com",
		"cn-shenzhen-finance-1": "gpdb.aliyuncs.com",
	}

	endpoint := endPointMap[region]
	if endpoint == "" {
		endpoint = "gpdb.aliyuncs.com"
	}

	config.Endpoint = tea.String(endpoint)
	_result = &gpdb20160503.Client{}
	_result, _err = gpdb20160503.NewClient(config)
	if _err != nil {
		return
	}

	_result.RegionId = config.RegionId
	return _result, _err
}

func createK8sClient(region string, config *openapi.Config) (_result *cs20151215.Client, _err error) {
	config.Endpoint = tea.String("cs." + region + ".aliyuncs.com")
	_result = &cs20151215.Client{}
	_result, _err = cs20151215.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createAcrClient(region string, config *openapi.Config) (_result *cr20181201.Client, _err error) {
	config.Endpoint = tea.String("cr." + region + ".aliyuncs.com")
	_result = &cr20181201.Client{}
	_result, _err = cr20181201.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createImsClient(region string, config *openapi.Config) (_result *ims20190815.Client, _err error) {
	config.Endpoint = tea.String("ims.aliyuncs.com")
	_result = &ims20190815.Client{}
	_result, _err = ims20190815.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createCasClient(region string, config *openapi.Config) (_result *cas20200407.Client, _err error) {
	endPointMap := map[string]string{
		"cn-hangzhou":    "cas.aliyuncs.com",
		"ap-southeast-3": "cas.ap-southeast-3.aliyuncs.com",
		"ap-southeast-1": "cas.ap-southeast-1.aliyuncs.com",
		"ap-southeast-5": "cas.ap-southeast-5.aliyuncs.com",
		"cn-hongkong":    "cas.cn-hongkong.aliyuncs.com",
		"eu-central-1":   "cas.eu-central-1.aliyuncs.com",
	}

	endpoint := endPointMap[region]
	if endpoint == "" {
		endpoint = "cas.aliyuncs.com"
	}

	config.Endpoint = tea.String(endpoint)
	_result = &cas20200407.Client{}
	_result, _err = cas20200407.NewClient(config)
	if _err != nil {
		return
	}
	_result, _err = cas20200407.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createMaxComputeClient(region string, config *openapi.Config) (_result *maxcompute20220104.Client, _err error) {
	config.Endpoint = tea.String("maxcompute." + region + ".aliyuncs.com")
	_result, _err = maxcompute20220104.NewClient(config)
	_result.RegionId = tea.String(region)
	return _result, _err
}

func createSLSClient(regionId string, config *openapi.Config) (_result *sls20201230.Client, _err error) {
	config.Endpoint = tea.String(regionId + ".log.aliyuncs.com")
	_result = &sls20201230.Client{}
	_result, _err = sls20201230.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

func createNASClient(regionId string, config *openapi.Config) (_result *nas.Client, _err error) {
	config.Endpoint = tea.String("nas." + regionId + ".aliyuncs.com")
	_result = &nas.Client{}
	_result, _err = nas.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for ESS
func createESSClient(regionId string, config *openapi.Config) (_result *ess20220222.Client, _err error) {
	_result = &ess20220222.Client{}
	config.Endpoint = tea.String("ess.aliyuncs.com")
	_result, _err = ess20220222.NewClient(config)
	if _err != nil {
		return
	}
	describeRegionsRequest := &ess20220222.DescribeRegionsRequest{}
	result, err := _result.DescribeRegions(describeRegionsRequest)
	if err != nil {
		return nil, err
	}
	for _, r := range result.Body.Regions {
		if tea.StringValue(r.RegionId) == regionId {
			config.Endpoint = r.RegionEndpoint
			break
		}
	}

	_result, _err = ess20220222.NewClient(config)
	_result.RegionId = config.RegionId
	return _result, _err
}

// returns the service connection for FC
func createFCClient(regionId string, config *openapi.Config) (_result *fc20230330.Client, _err error) {
	config.Endpoint = tea.String("fcv3." + regionId + ".aliyuncs.com")
	_result = &fc20230330.Client{}
	_result, _err = fc20230330.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// CreateTablestoreClient returns the service connection for Tablestore
func CreateTablestoreClient(regionId string, config *openapi.Config) (_result *tablestore20201209.Client, _err error) {
	config.Endpoint = tea.String("tablestore." + regionId + ".aliyuncs.com")
	_result = &tablestore20201209.Client{}
	_result, _err = tablestore20201209.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for DMS
func createDMSClient(regionId string, config *openapi.Config) (_result *dms_enterprise20181101.Client, _err error) {
	config.Endpoint = tea.String("dms-enterprise." + regionId + ".aliyuncs.com")
	_result = &dms_enterprise20181101.Client{}
	_result, _err = dms_enterprise20181101.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for CEN
func createCENClient(regionId string, config *openapi.Config) (_result *cbn20170912.Client, _err error) {
	config.Endpoint = tea.String("cbn.aliyuncs.com")
	_result = &cbn20170912.Client{}
	_result, _err = cbn20170912.NewClient(config)
	return _result, _err
}

// CreatePrivateLinkClient returns the service connection for PrivateLink
func createPrivateLinkClient(regionId string, config *openapi.Config) (_result *privatelink20200415.Client, _err error) {
	config.Endpoint = tea.String("privatelink." + regionId + ".aliyuncs.com")
	_result = &privatelink20200415.Client{}
	_result, _err = privatelink20200415.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for DNS
func createDNSClient(regionId string, config *openapi.Config) (_result *alidns20150109.Client, _err error) {
	if regionId == "cn-qingdao" || regionId == "cn-wulanchabu" {
		config.Endpoint = tea.String("dns.aliyuncs.com")
	} else {
		config.Endpoint = tea.String("alidns." + regionId + ".aliyuncs.com")
	}
	_result = &alidns20150109.Client{}
	_result, _err = alidns20150109.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for RocketMQ
func createRocketMQClient(regionId string, config *openapi.Config) (_result *rocketmq20220801.Client, _err error) {
	config.Endpoint = tea.String("rocketmq." + regionId + ".aliyuncs.com")
	_result = &rocketmq20220801.Client{}
	_result, _err = rocketmq20220801.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// createECPClient returns the service connection for Elastic Cloud Phone (ECP)
func createECPClient(regionId string, config *openapi.Config) (_result *eds_aic20230930.Client, _err error) {
	config.Endpoint = tea.String("eds-aic." + regionId + ".aliyuncs.com")
	_result = &eds_aic20230930.Client{}
	_result, _err = eds_aic20230930.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for CloudAPI
func CreateCloudAPIClient(regionId string, config *openapi.Config) (_result *cloudapi20160714.Client, _err error) {
	config.Endpoint = tea.String("apigateway." + regionId + ".aliyuncs.com")
	_result = &cloudapi20160714.Client{}
	_result, _err = cloudapi20160714.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for ARMS
func CreateARMSClient(regionId string, config *openapi.Config) (_result *arms20190808.Client, _err error) {
	if regionId == "cn-beijing-finance-1" || regionId == "me-east-1" {
		config.Endpoint = tea.String("arms.aliyuncs.com")
	} else {
		config.Endpoint = tea.String("arms." + regionId + ".aliyuncs.com")
	}
	_result = &arms20190808.Client{}
	_result, _err = arms20190808.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// returns the service connection for MSE
func CreateMSEClient(regionId string, config *openapi.Config) (_result *mse20190531.Client, _err error) {
	config.Endpoint = tea.String("mse." + regionId + ".aliyuncs.com")
	_result = &mse20190531.Client{}
	_result, _err = mse20190531.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

func CreateKMSClient(regionId string, config *openapi.Config) (_result *kms20160120.Client, _err error) {
	config.Endpoint = tea.String("kms." + regionId + ".aliyuncs.com")
	_result = &kms20160120.Client{}
	_result, _err = kms20160120.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

// createDDoSBGPClient DDoS
func createDDoSBGPClient(regionId string, config *openapi.Config) (_result *ddoscoo20200101.Client, _err error) {
	config.Endpoint = tea.String("ddoscoo." + regionId + ".aliyuncs.com")
	_result = &ddoscoo20200101.Client{}
	_result, _err = ddoscoo20200101.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

func createResourceClient(regionId string, config *openapi.Config) (_result *resourcecenter20221201.Client, err error) {
	if regionId == "ap-southeast-1" {
		config.Endpoint = tea.String("resourcecenter-intl.aliyuncs.com")
	} else {
		config.Endpoint = tea.String("resourcecenter.aliyuncs.com")
	}
	_result, _err := resourcecenter20221201.NewClient(config)
	_result.RegionId = tea.String(regionId)
	return _result, _err
}

func createActiontrailClient(regionId string, config *openapi.Config) (_result *actiontrail20200706.Client, _err error) {
	config.Endpoint = tea.String("actiontrail." + regionId + ".aliyuncs.com")
	_result = &actiontrail20200706.Client{}
	_result, _err = actiontrail20200706.NewClient(config)
	return _result, _err
}
