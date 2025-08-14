module github.com/cloudrec/aws

go 1.23

replace github.com/core-sdk => ../core-sdk

require (
	github.com/aws/aws-sdk-go-v2 v1.37.1
	github.com/aws/aws-sdk-go-v2/config v1.27.35
	github.com/aws/aws-sdk-go-v2/credentials v1.17.33
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.41.1
	github.com/aws/aws-sdk-go-v2/service/account v1.25.0
	github.com/aws/aws-sdk-go-v2/service/acm v1.34.0
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.29.0
	github.com/aws/aws-sdk-go-v2/service/appstream v1.46.0
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.54.1
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.61.1
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.41.1
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.49.4
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.45.4
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.54.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.30.1
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.54.1
	github.com/aws/aws-sdk-go-v2/service/configservice v1.53.1
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.44.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.237.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.36.6
	github.com/aws/aws-sdk-go-v2/service/ecs v1.60.1
	github.com/aws/aws-sdk-go-v2/service/efs v1.33.6
	github.com/aws/aws-sdk-go-v2/service/eks v1.66.2
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.44.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.28.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.38.2
	github.com/aws/aws-sdk-go-v2/service/fms v1.41.1
	github.com/aws/aws-sdk-go-v2/service/fsx v1.49.6
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.57.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.38.1
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.39.1
	github.com/aws/aws-sdk-go-v2/service/kms v1.41.3
	github.com/aws/aws-sdk-go-v2/service/lambda v1.73.0
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.46.1
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.52.1
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.49.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.90.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.46.2
	github.com/aws/aws-sdk-go-v2/service/route53domains v1.27.6
	github.com/aws/aws-sdk-go-v2/service/s3 v1.66.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.36.0
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.59.1
	github.com/aws/aws-sdk-go-v2/service/sns v1.34.8
	github.com/aws/aws-sdk-go-v2/service/sqs v1.39.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.55.5
	github.com/aws/smithy-go v1.22.5
	github.com/core-sdk v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.27.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.4.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.10.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.8 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
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
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yalp/jsonpath v0.0.0-20180802001716-5cc68e5049a0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
