module github.com/cloudrec/aws

go 1.23

replace github.com/core-sdk => ../core-sdk

require (
	github.com/core-sdk v0.0.0-00010101000000-000000000000
	github.com/aws/aws-sdk-go-v2 v1.32.5
	github.com/aws/aws-sdk-go-v2/config v1.27.35
	github.com/aws/aws-sdk-go-v2/credentials v1.17.33
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.41.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.170.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.36.6
	github.com/aws/aws-sdk-go-v2/service/efs v1.33.6
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.44.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.28.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.38.2
	github.com/aws/aws-sdk-go-v2/service/fsx v1.49.6
	github.com/aws/aws-sdk-go-v2/service/iam v1.38.1
	github.com/aws/aws-sdk-go-v2/service/rds v1.90.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.46.2
	github.com/aws/aws-sdk-go-v2/service/route53domains v1.27.6
	github.com/aws/aws-sdk-go-v2/service/s3 v1.66.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.55.5
	github.com/aws/smithy-go v1.22.1
	go.uber.org/zap v1.27.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.6 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.4.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.8 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/google/uuid v1.4.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/cobra v1.8.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/yalp/jsonpath v0.0.0-20180802001716-5cc68e5049a0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
