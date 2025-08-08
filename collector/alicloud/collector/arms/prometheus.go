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

package arms

import (
	"context"
	"encoding/json"

	arms20190808 "github.com/alibabacloud-go/arms-20190808/v8/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

func GetARMSPrometheusResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.ARMSPrometheus,
		ResourceTypeName:   collector.ARMSPrometheus,
		ResourceGroupType:  constant.MONITORING,
		Desc:               `https://api.aliyun.com/product/ARMS`,
		ResourceDetailFunc: GetPrometheusDetail,
		RowField: schema.RowField{
			ResourceId:   "$.PrometheusInstance.ClusterId",
			ResourceName: "$.PrometheusInstance.ClusterName",
		},
		Dimension: schema.Global,
	}
}

type PrometheusInstance struct {
	AgentStatus                string      `json:"agentStatus,omitempty"`
	ClusterId                  string      `json:"clusterId,omitempty"`
	ClusterName                string      `json:"clusterName,omitempty"`
	ClusterType                string      `json:"clusterType,omitempty"`
	CommercialConfig           interface{} `json:"commercialConfig,omitempty"`
	ControllerId               string      `json:"controllerId,omitempty"`
	CreateTime                 int64       `json:"createTime,omitempty"`
	Id                         int64       `json:"id,omitempty"`
	IsAdvancedClusterInstalled bool        `json:"isAdvancedClusterInstalled,omitempty"`
	IsClusterRunning           bool        `json:"isClusterRunning,omitempty"`
	IsControllerInstalled      bool        `json:"isControllerInstalled,omitempty"`
	IsIntegrationCenter        bool        `json:"isIntegrationCenter,omitempty"`
	RegionId                   string      `json:"regionId,omitempty"`
	UpdateTime                 int64       `json:"updateTime,omitempty"`
	UserId                     string      `json:"userId,omitempty"`
	SubClustersJson            string      `json:"subClustersJson,omitempty"`
}

type PrometheusDetail struct {
	PrometheusInstance *arms20190808.GetPrometheusInstanceResponseBodyData
	AlertRules         []*arms20190808.ListPrometheusAlertRulesResponseBodyPrometheusAlertRules
	MonitoringConfigs  []*arms20190808.ListPrometheusMonitoringResponseBodyData
	SubClusters        []SubClusterDetail
}

type SubClusterDetail struct {
	ClusterName string `json:"clusterName,omitempty"`
	ClusterId   string `json:"clusterId,omitempty"`
	ClusterType string `json:"clusterType,omitempty"`
	RegionId    string `json:"regionId,omitempty"`
}

func GetPrometheusDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).ARMS

	request := &arms20190808.ListPrometheusInstancesRequest{}

	response, err := cli.ListPrometheusInstancesWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPrometheusInstances error", zap.Error(err))
		return err
	}

	if response.Body == nil || response.Body.Data == nil {
		return nil
	}

	// Parse JSON response
	var instances []PrometheusInstance
	if err := json.Unmarshal([]byte(tea.StringValue(response.Body.Data)), &instances); err != nil {
		log.CtxLogger(ctx).Warn("Failed to unmarshal Prometheus instances", zap.Error(err))
		return err
	}

	for _, instance := range instances {
		if instance.ClusterId == "" {
			continue
		}

		clusterId := instance.ClusterId

		// Get detailed Prometheus instance configuration
		prometheusInstance := getPrometheusInstance(ctx, cli, clusterId)

		// Get alert rules for this Prometheus instance
		alertRules := listPrometheusAlertRules(ctx, cli, clusterId)

		// Get monitoring configurations
		monitoringConfigs := listPrometheusMonitoring(ctx, cli, clusterId)

		// Parse sub-clusters if available
		var subClusters []SubClusterDetail
		if instance.SubClustersJson != "" {
			if err := json.Unmarshal([]byte(instance.SubClustersJson), &subClusters); err != nil {
				log.CtxLogger(ctx).Warn("Failed to unmarshal SubClustersJson",
					zap.String("clusterId", clusterId), zap.Error(err))
			}
		}

		detail := PrometheusDetail{
			PrometheusInstance: prometheusInstance,
			AlertRules:         alertRules,
			MonitoringConfigs:  monitoringConfigs,
			SubClusters:        subClusters,
		}

		res <- detail
	}

	return nil
}

func getPrometheusInstance(ctx context.Context, cli *arms20190808.Client, clusterId string) *arms20190808.GetPrometheusInstanceResponseBodyData {
	request := &arms20190808.GetPrometheusInstanceRequest{
		ClusterId: tea.String(clusterId),
	}

	response, err := cli.GetPrometheusInstanceWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Warn("GetPrometheusInstance error",
			zap.String("clusterId", clusterId), zap.Error(err))
		return &arms20190808.GetPrometheusInstanceResponseBodyData{}
	}

	if response.Body == nil || response.Body.Data == nil {
		return &arms20190808.GetPrometheusInstanceResponseBodyData{}
	}

	return response.Body.Data
}

func listPrometheusAlertRules(ctx context.Context, cli *arms20190808.Client, clusterId string) []*arms20190808.ListPrometheusAlertRulesResponseBodyPrometheusAlertRules {
	request := &arms20190808.ListPrometheusAlertRulesRequest{
		ClusterId: tea.String(clusterId),
	}

	response, err := cli.ListPrometheusAlertRulesWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPrometheusAlertRules error",
			zap.String("clusterId", clusterId), zap.Error(err))
		return []*arms20190808.ListPrometheusAlertRulesResponseBodyPrometheusAlertRules{}
	}

	if response.Body == nil || response.Body.PrometheusAlertRules == nil {
		return []*arms20190808.ListPrometheusAlertRulesResponseBodyPrometheusAlertRules{}
	}

	return response.Body.PrometheusAlertRules
}

func listPrometheusMonitoring(ctx context.Context, cli *arms20190808.Client, clusterId string) []*arms20190808.ListPrometheusMonitoringResponseBodyData {
	request := &arms20190808.ListPrometheusMonitoringRequest{
		ClusterId: tea.String(clusterId),
	}

	response, err := cli.ListPrometheusMonitoringWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		log.CtxLogger(ctx).Warn("ListPrometheusMonitoring error",
			zap.String("clusterId", clusterId), zap.Error(err))
		return []*arms20190808.ListPrometheusMonitoringResponseBodyData{}
	}

	if response.Body == nil || response.Body.Data == nil {
		return []*arms20190808.ListPrometheusMonitoringResponseBodyData{}
	}

	return response.Body.Data
}
