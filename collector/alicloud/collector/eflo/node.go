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

package eflo

import (
	"context"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eflo-controller"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetNodeResource returns Eflo Node resource definition
func GetNodeResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.EfloNode,
		ResourceTypeName:   "EFLO Node",
		ResourceGroupType:  constant.COMPUTE,
		Desc:               "https://help.aliyun.com/document_detail/462123.html",
		ResourceDetailFunc: GetNodeDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Node.NodeId",
			ResourceName: "$.Node.Hostname",
			Address:      "$.Node.Networks[0].Ip",
		},
		Dimension: schema.Regional,
	}
}

// NodeDetail aggregates resource details
type NodeDetail struct {
	Node eflo_controller.NodesItem
}

// GetNodeDetail gets Eflo Node details
func GetNodeDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).EfloController

	resources, err := listNodes(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list nodes", zap.Error(err))
		return err
	}

	for _, node := range resources {
		res <- NodeDetail{Node: node}
	}

	return nil
}

// listNodes gets a list of Eflo Nodes
func listNodes(ctx context.Context, c *eflo_controller.Client) ([]eflo_controller.NodesItem, error) {
	var resources []eflo_controller.NodesItem
	var nextToken string
	maxResults := 100

	for {
		req := eflo_controller.CreateListFreeNodesRequest()
		req.NextToken = nextToken
		req.MaxResults = requests.NewInteger(maxResults)

		resp, err := c.ListFreeNodes(req)
		if err != nil {
			return nil, err
		}

		if resp.Nodes != nil && len(resp.Nodes) > 0 {
			resources = append(resources, resp.Nodes...)
		}

		if resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}

	return resources, nil
}
