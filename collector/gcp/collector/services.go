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
	"cloud.google.com/go/accesscontextmanager/apiv1"
	"cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"context"
	"fmt"
	"go.uber.org/zap"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/api/storage/v1"
	"google.golang.org/api/vpcaccess/v1"
)

type Services struct {
	Projects             []*resourcemanagerpb.Project
	StorageService       *storage.Service
	ComputeService       *compute.Service
	IamService           *iam.Service
	OrganizationsClient  *resourcemanager.OrganizationsClient
	ProjectsClient       *resourcemanager.ProjectsClient
	DNSService           *dns.Service
	ContainerService     *container.Service
	VpcAccessService     *vpcaccess.Service
	AccessContextManager *accesscontextmanager.Client
	CloudIdentity        *cloudidentity.Service
	Admin                *admin.Service
	CloudSQL             *sqladmin.Service
}

// Clone creates a new instance of Services with copied configuration
func (s *Services) Clone() schema.ServiceInterface {
	return &Services{}
}

func (s *Services) InitServices(cloudAccountParam schema.CloudAccountParam) (err error) {
	ctx := context.Background()
	param := cloudAccountParam.GCPCloudAccountParam
	clientOption := option.WithCredentialsJSON([]byte(param.CredentialsJson))

	projectsClient, err := resourcemanager.NewProjectsClient(ctx, clientOption)
	if err != nil {
		return err
	}
	defer func(projectsClient *resourcemanager.ProjectsClient) {
		err = projectsClient.Close()
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to close projects client: %v", err))
		}
	}(projectsClient)
	s.Projects = []*resourcemanagerpb.Project{}
	for project, err := range projectsClient.SearchProjects(ctx, &resourcemanagerpb.SearchProjectsRequest{}).All() {
		if err != nil {
			log.CtxLogger(ctx).Warn("SearchProjects error", zap.Error(err))
			s.Projects = append(s.Projects, &resourcemanagerpb.Project{ProjectId: param.ProjectId})
			//return err
		}
		s.Projects = append(s.Projects, project)
	}

	switch cloudAccountParam.ResourceType {
	case Bucket:
		svc, err := storage.NewService(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create storage client: %v", err))
		}
		s.StorageService = svc
	case CloudArmor, Instance, InstanceGroup, Firewall, ForwardingRule, BackendService, Address, Autoscaler, Subnetwork, Network, MachineImage, Route:
		svc, err := compute.NewService(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create compute client: %v", err))
		}
		s.ComputeService = svc
	case IAMServiceAccount:
		svc, err := iam.NewService(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create iam client: %v", err))
		}
		s.IamService = svc
	case Project:
		svc, err := resourcemanager.NewProjectsClient(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create projects client: %v", err))
		}
		s.ProjectsClient = svc
	case Organization:
		svc, err := resourcemanager.NewOrganizationsClient(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create organizations client: %v", err))
		}
		s.OrganizationsClient = svc
	case ResourceRecordSet:
		svc, err := dns.NewService(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create dns client: %v", err))
		}
		s.DNSService = svc
	case Cluster:
		svc, err := container.NewService(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create kubernetes client: %v", err))
		}
		s.ContainerService = svc
	case VPC:
		svc, err := vpcaccess.NewService(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create vpc client: %v", err))
		}
		s.VpcAccessService = svc
	case AccessPolicy, Perimeter:
		ACMSvc, err := accesscontextmanager.NewClient(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create access context manager client: %v", err))
		}
		s.AccessContextManager = ACMSvc

		OrgSvc, err := resourcemanager.NewOrganizationsClient(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create organizations client: %v", err))
		}
		s.OrganizationsClient = OrgSvc
	case CloudSQLInstance:
		svc, err := sqladmin.NewService(ctx, clientOption)
		if err != nil {
			log.CtxLogger(ctx).Warn("Failed to create sql admin client:", zap.Error(err))
		}
		s.CloudSQL = svc
	case GoogleGroup:
		svc, err := admin.NewService(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create admin client: %v", err))
		}
		s.Admin = svc

		s.OrganizationsClient, err = resourcemanager.NewOrganizationsClient(ctx, clientOption)
		if err != nil {
			log.GetWLogger().Warn(fmt.Sprintf("Failed to create Organizations client: %v", err))
		}
	}

	return nil
}
