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
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/fms"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/smithy-go/logging"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"time"
)

// Services contains regional client of AWS services
type Services struct {
	EC2                     *ec2.Client
	IAM                     *iam.Client
	S3                      *s3.Client
	Lambda                  *lambda.Client
	KMS                     *kms.Client
	ECR                     *ecr.Client
	ElastiCache             *elasticache.Client
	ELB                     *elasticloadbalancingv2.Client
	CLB                     *elasticloadbalancing.Client
	FSx                     *fsx.Client
	RDS                     *rds.Client
	Route53Domains          *route53domains.Client
	Route53                 *route53.Client
	CloudFront              *cloudfront.Client
	WAFv2                   *wafv2.Client
	CloudTrail              *cloudtrail.Client
	APIGatewayV2            *apigatewayv2.Client
	ACM                     *acm.Client
	SecretsManager          *secretsmanager.Client
	AutoScaling             *autoscaling.Client
	ECS                     *ecs.Client
	EKS                     *eks.Client
	DynamoDB                *dynamodb.Client
	CloudFormation          *cloudformation.Client
	GuardDuty               *guardduty.Client
	EFS                     *efs.Client
	SNS                     *sns.Client
	SQS                     *sqs.Client
	CloudWatch              *cloudwatch.Client
	CloudWatchLogs          *cloudwatchlogs.Client
	Account                 *account.Client
	Config                  *configservice.Client
	AppStream               *appstream.Client
	AccessAnalyzer          *accessanalyzer.Client
	CognitoIdentityProvider *cognitoidentityprovider.Client
	CognitoIdentity         *cognitoidentity.Client
	FMS                     *fms.Client
	Inspector2              *inspector2.Client
	SecurityHub             *securityhub.Client
	Macie                   *macie2.Client
	NetworkFirewall         *networkfirewall.Client
	OpenSearch              *opensearch.Client
}

// Clone creates a new instance of Services
func (s *Services) Clone() schema.ServiceInterface {
	// Return a new empty instance
	// All clients will be initialized when InitServices is called
	return &Services{}
}

// AssessCollectionTrigger determines whether asset collection should be performed for the cloud account
// Returns true if collection should proceed, false if it should be skipped
// This can be used to skip collection when credentials are invalid or no changes occurred
// AssessCollectionTrigger determines whether collection should be performed for the given cloud account
// Returns CollectRecordInfo containing collection decision and metadata
func (s *Services) AssessCollectionTrigger(param schema.CloudAccountParam) schema.CollectRecordInfo {
	// TODO: Implement logic to check if collection should be performed
	// For example:
	// - Check if credentials are valid
	// - Check if there were recent changes in the account
	// - Check if the last collection was recent enough
	// - Check if the account is in maintenance mode

	startTime := time.Now().Format("2006-01-02T15:04:05Z")
	recordInfo := schema.CollectRecordInfo{
		CloudAccountId:   param.CloudAccountId,
		Platform:         param.Platform,
		StartTime:        startTime,
		EndTime:          "",   // Will be set when collection completes
		EnableCollection: true, // Default implementation: always collect
	}

	return recordInfo
}

func (s *Services) InitServices(cloudAccountParam schema.CloudAccountParam) (err error) {
	param := cloudAccountParam.CommonCloudAccountParam
	region := param.Region
	ak := param.AK
	sk := param.SK
	cfg, err := buildConfigWithRegion(region, ak, sk)
	if err != nil {
		// todo
		return err
	}

	// init client of aws services
	switch cloudAccountParam.ResourceType {
	case EC2, ElasticIP, NetworkAcl, SecurityGroup, Vpc, VPCEndpointService, FlowLog, NetworkInterface:
		s.EC2 = initEC2Client(cfg)
	case Bucket:
		s.S3 = initS3Client(cfg)
	case Registry, Repository:
		s.ECR = initECRClient(cfg)
	case EFSFileSystem:
		s.EFS = initEFSClient(cfg)
	case ElastiCache:
		s.ElastiCache = initElastiCacheClient(cfg)
	case ELB:
		s.ELB = initELBClient(cfg)
	case CLB:
		s.CLB = initCLBClient(cfg)
	case FSxFileSystem:
		s.FSx = initFSxClient(cfg)
	case AccountSettings, UserGroup, Role, User:
		s.IAM = initIAMClient(cfg)
	case RDS:
		s.RDS = initRDSClient(cfg)
		s.EC2 = initEC2Client(cfg)
	case Domain:
		s.Route53Domains = initRoute53DomainsClient(cfg)
	case ResourceRecordSet:
		s.Route53 = initRoute53Client(cfg)
	case CDN:
		s.CloudFront = initCloudFrontClient(cfg)
	case KMS:
		s.KMS = initKMSClient(cfg)
	case WebACL:
		s.WAFv2 = initWafv2Client(cfg)
	case CloudTrail:
		s.CloudTrail = initCloudTrailClient(cfg)
	case Lambda:
		s.Lambda = initLambdaClient(cfg)
	case AutoScalingGroup:
		s.AutoScaling = initAutoScalingClient(cfg)
	case ECSCluster, ECSTaskDefinition:
		s.ECS = initECSClient(cfg)
	case EKSCluster:
		s.EKS = initEKSClient(cfg)
	case DynamoDBTable:
		s.DynamoDB = initDynamoDBClient(cfg)
	case CloudFormationStack:
		s.CloudFormation = initCloudFormationClient(cfg)
	case GuardDuty:
		s.GuardDuty = initGuardDutyClient(cfg)
	case SNSTopic:
		s.SNS = initSNSClient(cfg)
	case CloudWatchAlarm:
		s.CloudWatch = initCloudWatchClient(cfg)
	case CloudWatchLogGroup:
		s.CloudWatchLogs = initCloudWatchLogsClient(cfg)
	case Account:
		s.Account = initAccountClient(cfg)
	case Config:
		s.Config = initConfigServiceClient(cfg)
	case AppStreamFleet:
		s.AppStream = initAppStreamClient(cfg)
	case APIGatewayV2API:
		s.APIGatewayV2 = initAPIGatewayV2Client(cfg)
	case Certificate:
		s.ACM = initACMClient(cfg)
	case Secret:
		s.SecretsManager = initSecretsManagerClient(cfg)
	case SQSQueue:
		s.SQS = initSQSClient(cfg)
	case AccessAnalyzer:
		s.AccessAnalyzer = initAccessAnalyzerClient(cfg)
	case CognitoUserPool, CognitoIdentityPool:
		s.CognitoIdentityProvider = initCognitoIdentityProviderClient(cfg)
		s.CognitoIdentity = initCognitoIdentityClient(cfg)
	case FMS:
		s.FMS = initFMSClient(cfg)
	case Inspector2:
		s.Inspector2 = initInspector2Client(cfg)
	case SecurityHub:
		s.SecurityHub = initSecurityHubClient(cfg)
	case MacieFinding, MacieJob, MacieSession:
		s.Macie = initMacieClient(cfg)
	case NetworkFirewall:
		s.NetworkFirewall = initNetworkFirewallClient(cfg)
	case OpenSearch:
		s.OpenSearch = initOpenSearchClient(cfg)
	}

	return nil
}

func initConfigServiceClient(cfg aws.Config) *configservice.Client {
	return configservice.NewFromConfig(cfg)
}

func initAccountClient(cfg aws.Config) *account.Client {
	return account.NewFromConfig(cfg)
}

func initCloudWatchClient(cfg aws.Config) *cloudwatch.Client {
	return cloudwatch.NewFromConfig(cfg)
}

func initCloudWatchLogsClient(cfg aws.Config) *cloudwatchlogs.Client {
	return cloudwatchlogs.NewFromConfig(cfg)
}

func initGuardDutyClient(cfg aws.Config) *guardduty.Client {
	return guardduty.NewFromConfig(cfg)
}

func initKMSClient(cfg aws.Config) *kms.Client {
	return kms.NewFromConfig(cfg)
}

func initECRClient(cfg aws.Config) *ecr.Client {
	return ecr.NewFromConfig(cfg)
}

func initElastiCacheClient(cfg aws.Config) *elasticache.Client {
	return elasticache.NewFromConfig(cfg)
}

func initWafv2Client(cfg aws.Config) *wafv2.Client {
	cfg.Region = "us-east-1"
	return wafv2.NewFromConfig(cfg)
}

func initCloudFrontClient(cfg aws.Config) *cloudfront.Client {
	return cloudfront.NewFromConfig(cfg)
}

func initRoute53DomainsClient(cfg aws.Config) *route53domains.Client {
	return route53domains.NewFromConfig(cfg)
}

func initRoute53Client(cfg aws.Config) *route53.Client {
	return route53.NewFromConfig(cfg)
}

func initRDSClient(cfg aws.Config) *rds.Client {
	return rds.NewFromConfig(cfg)
}

func initFSxClient(cfg aws.Config) *fsx.Client {
	return fsx.NewFromConfig(cfg)
}

func initEFSClient(cfg aws.Config) *efs.Client {
	return efs.NewFromConfig(cfg)
}

func initIAMClient(cfg aws.Config) *iam.Client {
	return iam.NewFromConfig(cfg)
}

func initS3Client(cfg aws.Config) *s3.Client {
	return s3.NewFromConfig(cfg)
}

func initEC2Client(cfg aws.Config) *ec2.Client {
	return ec2.NewFromConfig(cfg)
}

func initCLBClient(cfg aws.Config) *elasticloadbalancing.Client {
	return elasticloadbalancing.NewFromConfig(cfg)
}
func initELBClient(cfg aws.Config) *elasticloadbalancingv2.Client {
	return elasticloadbalancingv2.NewFromConfig(cfg)
}

func initCloudTrailClient(cfg aws.Config) *cloudtrail.Client {
	return cloudtrail.NewFromConfig(cfg)
}

func initLambdaClient(cfg aws.Config) *lambda.Client {
	return lambda.NewFromConfig(cfg)
}

func initAutoScalingClient(cfg aws.Config) *autoscaling.Client {
	return autoscaling.NewFromConfig(cfg)
}

func initECSClient(cfg aws.Config) *ecs.Client {
	return ecs.NewFromConfig(cfg)
}

func initEKSClient(cfg aws.Config) *eks.Client {
	return eks.NewFromConfig(cfg)
}

func initDynamoDBClient(cfg aws.Config) *dynamodb.Client {
	return dynamodb.NewFromConfig(cfg)
}

func initCloudFormationClient(cfg aws.Config) *cloudformation.Client {
	return cloudformation.NewFromConfig(cfg)
}

func initSNSClient(cfg aws.Config) *sns.Client {
	return sns.NewFromConfig(cfg)
}

func initSQSClient(cfg aws.Config) *sqs.Client {
	return sqs.NewFromConfig(cfg)
}

func initAppStreamClient(cfg aws.Config) *appstream.Client {
	return appstream.NewFromConfig(cfg)
}

func initAPIGatewayV2Client(cfg aws.Config) *apigatewayv2.Client {
	return apigatewayv2.NewFromConfig(cfg)
}

func initACMClient(cfg aws.Config) *acm.Client {
	return acm.NewFromConfig(cfg)
}

func initSecretsManagerClient(cfg aws.Config) *secretsmanager.Client {
	return secretsmanager.NewFromConfig(cfg)
}

func initAccessAnalyzerClient(cfg aws.Config) *accessanalyzer.Client {
	return accessanalyzer.NewFromConfig(cfg)
}

func initCognitoIdentityProviderClient(cfg aws.Config) *cognitoidentityprovider.Client {
	return cognitoidentityprovider.NewFromConfig(cfg)
}

func initCognitoIdentityClient(cfg aws.Config) *cognitoidentity.Client {
	return cognitoidentity.NewFromConfig(cfg)
}

func initFMSClient(cfg aws.Config) *fms.Client {
	return fms.NewFromConfig(cfg)
}

func initInspector2Client(cfg aws.Config) *inspector2.Client {
	return inspector2.NewFromConfig(cfg)
}

func initSecurityHubClient(cfg aws.Config) *securityhub.Client {
	return securityhub.NewFromConfig(cfg)
}

func initMacieClient(cfg aws.Config) *macie2.Client {
	return macie2.NewFromConfig(cfg)
}

func initNetworkFirewallClient(cfg aws.Config) *networkfirewall.Client {
	return networkfirewall.NewFromConfig(cfg)
}

func initOpenSearchClient(cfg aws.Config) *opensearch.Client {
	return opensearch.NewFromConfig(cfg)
}

// BuildConfigWithRegion returns validate aws route with the region passed in
func buildConfigWithRegion(region string, ak string, sk string) (aws.Config, error) {
	var loggerBuf bytes.Buffer
	logger := logging.NewStandardLogger(&loggerBuf)

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithLogger(logger), //could be application logger ,https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#ClientLogMode
		config.WithClientLogMode(aws.LogRetries|aws.LogRequest),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, "")),
		config.WithRegion(region),
	)
	if err != nil {
		log.GetWLogger().Error(fmt.Sprintf("fail to build config, %v", err))
		return aws.Config{}, err
	}

	return cfg, nil
}
