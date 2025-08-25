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
	"github.com/cloudrec/aws/collector"
	"github.com/cloudrec/aws/collector/accessanalyzer"
	"github.com/cloudrec/aws/collector/account"
	"github.com/cloudrec/aws/collector/acm"
	"github.com/cloudrec/aws/collector/apigateway"
	"github.com/cloudrec/aws/collector/appstream"
	"github.com/cloudrec/aws/collector/autoscaling"
	"github.com/cloudrec/aws/collector/cloudformation"
	"github.com/cloudrec/aws/collector/cloudfront"
	"github.com/cloudrec/aws/collector/cloudtrail"
	"github.com/cloudrec/aws/collector/cloudwatch"
	"github.com/cloudrec/aws/collector/cognito"
	"github.com/cloudrec/aws/collector/config"
	"github.com/cloudrec/aws/collector/dynamodb"
	"github.com/cloudrec/aws/collector/ec2"
	"github.com/cloudrec/aws/collector/ecr"
	"github.com/cloudrec/aws/collector/ecs"
	"github.com/cloudrec/aws/collector/efs"
	"github.com/cloudrec/aws/collector/eks"
	"github.com/cloudrec/aws/collector/elasticache"
	"github.com/cloudrec/aws/collector/elasticloadbalancing"
	"github.com/cloudrec/aws/collector/fms"
	"github.com/cloudrec/aws/collector/fsx"
	"github.com/cloudrec/aws/collector/guardduty"
	"github.com/cloudrec/aws/collector/iam"
	"github.com/cloudrec/aws/collector/inspector2"
	"github.com/cloudrec/aws/collector/kms"
	"github.com/cloudrec/aws/collector/lambda"
	"github.com/cloudrec/aws/collector/macie"
	"github.com/cloudrec/aws/collector/networkfirewall"
	"github.com/cloudrec/aws/collector/opensearch"
	"github.com/cloudrec/aws/collector/rds"
	"github.com/cloudrec/aws/collector/route53"
	"github.com/cloudrec/aws/collector/s3"
	"github.com/cloudrec/aws/collector/secretsmanager"
	"github.com/cloudrec/aws/collector/securityhub"
	"github.com/cloudrec/aws/collector/sns"
	"github.com/cloudrec/aws/collector/sqs"
	"github.com/cloudrec/aws/collector/wafv2"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
)

func GetPlatformConfig() *schema.Platform {
	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.AWS),
		Resources: []schema.Resource{

			cloudfront.GetDistributionResource(),
			ec2.GetInstanceResource(),
			ec2.GetElasticIPResource(),
			ec2.GetNetworkAclResource(),
			ec2.GetSecurityGroupResource(),
			ec2.GetVPCResource(),
			ec2.GetVpcEndpointServiceResource(),
			ec2.GetFlowLogResource(),
			ec2.GetNetworkInterfaceResource(),
			rds.GetRDSInstanceResource(),
			elasticloadbalancing.GetELBResource(),
			elasticloadbalancing.GetCLBResource(),
			wafv2.GetWebACLResource(),
			route53.GetDomainResource(),
			route53.GetResourceRecordSetResource(),
			s3.GetS3BucketResource(),
			ecr.GetRegistryResource(),
			ecr.GetRepositoryResource(),
			efs.GetEFSFileSystemResource(),
			elasticache.GetElastiCacheClusterResource(),
			fsx.GetFsxFileSystemResource(),
			iam.GetUserResource(),
			iam.GetRoleResource(),
			iam.GetGroupResource(),
			iam.GetAccountSettingsResource(),
			iam.GetPolicyResource(),
			kms.GetKeyResource(),
			config.GetRecorderResource(),
			guardduty.GetDetectorResource(),
			cloudtrail.GetTrailResource(),
			lambda.GetFunctionResource(),
			autoscaling.GetGroupResource(),
			ecs.GetClusterResource(),
			ecs.GetTaskDefinitionResource(),
			eks.GetClusterResource(),
			dynamodb.GetTableResource(),
			cloudformation.GetStackResource(),
			cloudwatch.GetAlarmResource(),
			cloudwatch.GetLogGroupResource(),
			account.GetAccountResource(),
			appstream.GetFleetResource(),
			apigateway.GetAPIV2Resource(),
			acm.GetCertificateResource(),
			secretsmanager.GetSecretResource(),
			sns.GetSNSTopicResource(),
			sqs.GetSQSQueueResource(),
			accessanalyzer.GetAnalyzerResource(),
			cognito.GetUserPoolResource(),
			cognito.GetIdentityPoolResource(),
			fms.GetPolicyResource(),
			inspector2.GetFindingResource(),
			inspector2.GetCoverageResource(),
			securityhub.GetFindingResource(),
			macie.GetFindingResource(),
			macie.GetClassificationJobResource(),
			macie.GetMacieSessionResource(),
			networkfirewall.GetFirewallResource(),
			networkfirewall.GetRuleGroupResource(),
			opensearch.GetDomainResource(),
		},
		Service: &collector.Services{},

		// All of AWS Regions as default regions
		DefaultRegions: []string{
			"cn-north-1",
			"cn-northwest-1",
			"us-east-2",
			"us-east-1",
			"us-west-1",
			"us-west-2",
			"af-south-1",
			"ap-east-1",
			"ap-south-2",
			"ap-southeast-3",
			"ap-southeast-5",
			"ap-southeast-4",
			"ap-south-1",
			"ap-northeast-3",
			"ap-northeast-2",
			"ap-southeast-1",
			"ap-southeast-2",
			"ap-northeast-1",
			"ca-central-1",
			"ca-west-1",
			"eu-central-1",
			"eu-west-1",
			"eu-west-2",
			"eu-south-1",
			"eu-west-3",
			"eu-south-2",
			"eu-north-1",
			"eu-central-2",
			"il-central-1",
			"me-south-1",
			"me-central-1",
			"sa-east-1"},
	})

}
