module cloudrec

go 1.23.0

replace github.com/core-sdk => ./core-sdk

replace github.com/cloudrec/alicloud => ./alicloud

replace github.com/cloudrec/hws => ./hws

replace github.com/cloudrec/aws => ./aws

replace github.com/cloudrec/tencent => ./tencent

replace github.com/cloudrec/baidu => ./baidu

replace github.com/cloudrec/ksyun => ./ksyun

require (
	github.com/cloudrec/alicloud v0.0.0-00010101000000-000000000000
	github.com/cloudrec/aws v0.0.0-00010101000000-000000000000
	github.com/cloudrec/baidu v0.0.0-00010101000000-000000000000
	github.com/cloudrec/hws v0.0.0-00010101000000-000000000000
	github.com/cloudrec/ksyun v0.0.0-00010101000000-000000000000
	github.com/cloudrec/tencent v0.0.0-00010101000000-000000000000
	github.com/core-sdk v0.0.0-00010101000000-000000000000
)

require (
	github.com/KscSDK/ksc-sdk-go v0.10.0 // indirect
	github.com/alibabacloud-go/actiontrail-20200706/v3 v3.2.0 // indirect
	github.com/alibabacloud-go/adb-20190315/v4 v4.1.4 // indirect
	github.com/alibabacloud-go/alb-20200616/v2 v2.2.3 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-pop v0.0.6 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-sls v0.3.0 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-sls-util v0.3.0 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-spi v0.0.5 // indirect
	github.com/alibabacloud-go/alidns-20150109/v4 v4.5.7 // indirect
	github.com/alibabacloud-go/apig-20240327/v3 v3.2.2 // indirect
	github.com/alibabacloud-go/arms-20190808/v8 v8.1.6 // indirect
	github.com/alibabacloud-go/cas-20200407/v3 v3.0.1 // indirect
	github.com/alibabacloud-go/cbn-20170912/v2 v2.2.1 // indirect
	github.com/alibabacloud-go/cloudapi-20160714/v5 v5.5.0 // indirect
	github.com/alibabacloud-go/cloudfw-20171207/v7 v7.0.4 // indirect
	github.com/alibabacloud-go/cr-20181201/v2 v2.5.0 // indirect
	github.com/alibabacloud-go/cs-20151215/v5 v5.7.10 // indirect
	github.com/alibabacloud-go/darabonba-array v0.1.0 // indirect
	github.com/alibabacloud-go/darabonba-encode-util v0.0.2 // indirect
	github.com/alibabacloud-go/darabonba-map v0.0.2 // indirect
	github.com/alibabacloud-go/darabonba-openapi/v2 v2.1.9 // indirect
	github.com/alibabacloud-go/darabonba-signature-util v0.0.7 // indirect
	github.com/alibabacloud-go/darabonba-string v1.0.2 // indirect
	github.com/alibabacloud-go/ddoscoo-20200101/v3 v3.6.0 // indirect
	github.com/alibabacloud-go/dds-20151201/v8 v8.0.0 // indirect
	github.com/alibabacloud-go/debug v1.0.1 // indirect
	github.com/alibabacloud-go/dms-enterprise-20181101 v1.63.0 // indirect
	github.com/alibabacloud-go/eds-aic-20230930/v4 v4.11.5 // indirect
	github.com/alibabacloud-go/elasticsearch-20170613/v3 v3.0.7 // indirect
	github.com/alibabacloud-go/endpoint-util v1.1.0 // indirect
	github.com/alibabacloud-go/ess-20220222/v2 v2.10.1 // indirect
	github.com/alibabacloud-go/fc-20230330/v4 v4.1.4 // indirect
	github.com/alibabacloud-go/gpdb-20160503/v3 v3.9.1 // indirect
	github.com/alibabacloud-go/hitsdb-20200615/v5 v5.7.0 // indirect
	github.com/alibabacloud-go/ims-20190815/v4 v4.1.1 // indirect
	github.com/alibabacloud-go/kms-20160120/v3 v3.2.3 // indirect
	github.com/alibabacloud-go/maxcompute-20220104 v1.4.1 // indirect
	github.com/alibabacloud-go/mse-20190531/v5 v5.14.1 // indirect
	github.com/alibabacloud-go/nas-20170626/v3 v3.5.0 // indirect
	github.com/alibabacloud-go/nlb-20220430/v3 v3.1.1 // indirect
	github.com/alibabacloud-go/oceanbasepro-20190901/v8 v8.2.0 // indirect
	github.com/alibabacloud-go/openapi-util v0.1.1 // indirect
	github.com/alibabacloud-go/openplatform-20191219/v2 v2.0.1 // indirect
	github.com/alibabacloud-go/polardb-20170801/v6 v6.2.1 // indirect
	github.com/alibabacloud-go/privatelink-20200415/v5 v5.0.2 // indirect
	github.com/alibabacloud-go/r-kvstore-20150101/v5 v5.2.1 // indirect
	github.com/alibabacloud-go/rds-20140815/v6 v6.1.0 // indirect
	github.com/alibabacloud-go/resourcecenter-20221201 v1.4.0 // indirect
	github.com/alibabacloud-go/rocketmq-20220801 v1.5.3 // indirect
	github.com/alibabacloud-go/sas-20181203/v3 v3.4.0 // indirect
	github.com/alibabacloud-go/selectdb-20230522/v3 v3.1.0 // indirect
	github.com/alibabacloud-go/slb-20140515/v4 v4.0.9 // indirect
	github.com/alibabacloud-go/sls-20201230/v6 v6.9.2 // indirect
	github.com/alibabacloud-go/tablestore-20201209 v1.0.1 // indirect
	github.com/alibabacloud-go/tea v1.3.10 // indirect
	github.com/alibabacloud-go/tea-fileform v1.1.1 // indirect
	github.com/alibabacloud-go/tea-oss-sdk v1.1.3 // indirect
	github.com/alibabacloud-go/tea-oss-utils v1.1.0 // indirect
	github.com/alibabacloud-go/tea-utils v1.3.6 // indirect
	github.com/alibabacloud-go/tea-utils/v2 v2.0.7 // indirect
	github.com/alibabacloud-go/tea-xml v1.1.3 // indirect
	github.com/alibabacloud-go/waf-openapi-20211001/v4 v4.6.0 // indirect
	github.com/alibabacloud-go/yundun-bastionhost-20191209/v2 v2.3.0 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v1.63.48 // indirect
	github.com/aliyun/alibabacloud-oss-go-sdk-v2 v1.2.1 // indirect
	github.com/aliyun/credentials-go v1.4.5 // indirect
	github.com/aws/aws-sdk-go v1.44.320 // indirect
	github.com/aws/aws-sdk-go-v2 v1.37.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.27.35 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.33 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.41.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/account v1.25.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/acm v1.34.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.29.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/appstream v1.46.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.54.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.61.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.41.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.49.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.45.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.54.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.54.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/configservice v1.53.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.44.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.237.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.36.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecs v1.60.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/efs v1.33.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/eks v1.66.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.44.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.28.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.38.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/fms v1.41.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/fsx v1.49.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.57.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.38.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.39.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.4.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.10.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.41.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/lambda v1.73.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.46.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.52.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.49.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/rds v1.90.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.46.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53domains v1.27.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.66.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.59.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sns v1.34.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.39.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.55.5 // indirect
	github.com/aws/smithy-go v1.22.5 // indirect
	github.com/baidubce/bce-sdk-go v0.9.229 // indirect
	github.com/clbanning/mxj v1.8.4 // indirect
	github.com/clbanning/mxj/v2 v2.7.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/huaweicloud/huaweicloud-sdk-go-obs v3.25.4+incompatible // indirect
	github.com/huaweicloud/huaweicloud-sdk-go-v3 v0.1.105 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kingsoftcloud/sdk-go/v2 v2.1.8 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/ks3sdklib/aws-sdk-go v1.6.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mozillazg/go-httpheader v0.2.1 // indirect
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/shirou/gopsutil/v3 v3.24.2 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/cobra v1.8.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam v1.0.1113 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdb v1.0.1113 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cfs v1.0.1113 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb v1.0.1113 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.1115 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm v1.0.1114 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod v1.0.1115 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/mariadb v1.0.1113 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/postgres v1.0.1113 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sqlserver v1.0.1113 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc v1.0.1113 // indirect
	github.com/tencentyun/cos-go-sdk-v5 v0.7.59 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yalp/jsonpath v0.0.0-20180802001716-5cc68e5049a0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.mongodb.org/mongo-driver v1.12.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d // indirect
	golang.org/x/net v0.32.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/time v0.8.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
