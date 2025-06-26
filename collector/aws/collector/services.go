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
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/smithy-go/logging"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Services contains regional client of AWS services
type Services struct {
	EC2            *ec2.Client
	S3             *s3.Client
	CLB            *elasticloadbalancing.Client
	ELB            *elasticloadbalancingv2.Client
	IAM            *iam.Client
	EFS            *efs.Client
	FSx            *fsx.Client
	RDS            *rds.Client
	Route53        *route53.Client
	Route53Domains *route53domains.Client
	CloudFront     *cloudfront.Client
	WAFv2          *wafv2.Client
	ElastiCache    *elasticache.Client
	ECR            *ecr.Client
}

// Clone creates a new instance of Services
func (s *Services) Clone() schema.ServiceInterface {
	// Return a new empty instance
	// All clients will be initialized when InitServices is called
	return &Services{}
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
	case EC2, ElasticIP, NetworkAcl, SecurityGroup, Vpc:
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
	case WebACL:
		s.WAFv2 = initWafv2Client(cfg)
	}

	return nil
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
