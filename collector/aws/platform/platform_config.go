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
	"github.com/cloudrec/aws/collector"
	"github.com/cloudrec/aws/collector/cloudfront"
	"github.com/cloudrec/aws/collector/ec2"
	"github.com/cloudrec/aws/collector/ecr"
	"github.com/cloudrec/aws/collector/efs"
	"github.com/cloudrec/aws/collector/elasticache"
	"github.com/cloudrec/aws/collector/elasticloadbalancing"
	"github.com/cloudrec/aws/collector/fsx"
	"github.com/cloudrec/aws/collector/iam"
	"github.com/cloudrec/aws/collector/rds"
	"github.com/cloudrec/aws/collector/route53"
	"github.com/cloudrec/aws/collector/s3"
	"github.com/cloudrec/aws/collector/wafv2"
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
