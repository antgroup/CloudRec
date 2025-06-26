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

package platfrom

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"github.com/cloudrec/gcp/collector"
	"github.com/cloudrec/gcp/collector/accesscontextmanager"
	"github.com/cloudrec/gcp/collector/admin"
	"github.com/cloudrec/gcp/collector/cloudresourcemanager"
	"github.com/cloudrec/gcp/collector/cloudsql"
	"github.com/cloudrec/gcp/collector/cloudstorage"
	"github.com/cloudrec/gcp/collector/computeengine"
	"github.com/cloudrec/gcp/collector/dns"
	"github.com/cloudrec/gcp/collector/iam"
	"github.com/cloudrec/gcp/collector/k8sengine"
	"github.com/cloudrec/gcp/collector/vpc"
)

func GetPlatformConfig() *schema.Platform {
	regions := []string{
		"gcp-region"}

	return schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.GCP),
		Resources: []schema.Resource{
			cloudstorage.GetBucketResource(),
			iam.GetIAMServiceAccountResource(),
			dns.GetResourceRecordSetResource(),
			k8sengine.GetClusterResource(),
			vpc.GetVPCResource(),
			computeengine.GetInstanceResource(),
			computeengine.GetAddressResource(),
			computeengine.GetAutoscalersResource(),
			computeengine.GetBackendServiceResource(),
			computeengine.GetFirewallResource(),
			computeengine.GetForwardingRuleResource(),
			computeengine.GetInstanceGroupResource(),
			computeengine.GetSubnetworkResource(),
			computeengine.GetMachineImageResource(),
			computeengine.GetNetworkResource(),
			computeengine.GetRouterResource(),
			computeengine.GetCloudArmorResource(),
			accesscontextmanager.GetPerimeterResource(),
			accesscontextmanager.GetAccessPolicyResource(),
			accesscontextmanager.GetGcpUserAccessBindingResource(),
			cloudresourcemanager.GetOrganizationResource(),
			cloudresourcemanager.GetProjectResource(),
			admin.GetGroupResource(),
			cloudsql.GetInstanceResource(),
		},

		Service:        &collector.Services{},
		DefaultRegions: regions,
	})
}
