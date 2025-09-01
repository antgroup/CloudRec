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

package dynamodb

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/cloudrec/aws/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

// GetTableResource returns a Table Resource
func GetTableResource() schema.Resource {
	return schema.Resource{
		ResourceType:       collector.DynamoDBTable,
		ResourceTypeName:   "DynamoDB Table",
		ResourceGroupType:  constant.DATABASE,
		Desc:               `https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DescribeTable.html`,
		ResourceDetailFunc: GetTableDetail,
		RowField: schema.RowField{
			ResourceId:   "$.Table.TableArn",
			ResourceName: "$.Table.TableName",
		},
		Dimension: schema.Regional,
	}
}

// TableDetail aggregates all information for a single DynamoDB table.
type TableDetail struct {
	Table             *types.TableDescription
	ContinuousBackups *types.ContinuousBackupsDescription
}

// GetTableDetail fetches the details for all DynamoDB tables in a region.
func GetTableDetail(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	client := service.(*collector.Services).DynamoDB

	tableNames, err := listTables(ctx, client)
	if err != nil {
		log.CtxLogger(ctx).Error("failed to list dynamodb tables", zap.Error(err))
		return err
	}

	for _, tableName := range tableNames {

		table, err := describeTable(ctx, client, tableName)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe dynamodb table", zap.String("tableName", tableName), zap.Error(err))
		}
		continuousBackups, err := describeContinuousBackups(ctx, client, tableName)
		if err != nil {
			log.CtxLogger(ctx).Warn("failed to describe continuous backups", zap.String("tableName", tableName), zap.Error(err))
		}
		res <- &TableDetail{
			Table:             table,
			ContinuousBackups: continuousBackups,
		}
	}

	return nil
}

// listTables retrieves all DynamoDB table names in a region.
func listTables(ctx context.Context, c *dynamodb.Client) ([]string, error) {
	var tableNames []string
	paginator := dynamodb.NewListTablesPaginator(c, &dynamodb.ListTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		tableNames = append(tableNames, page.TableNames...)
	}
	return tableNames, nil
}

// describeTable retrieves the details for a single table.
func describeTable(ctx context.Context, c *dynamodb.Client, tableName string) (*types.TableDescription, error) {
	output, err := c.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &tableName})
	if err != nil {
		return nil, err
	}
	return output.Table, nil
}

// describeContinuousBackups retrieves the continuous backup details for a single table.
func describeContinuousBackups(ctx context.Context, c *dynamodb.Client, tableName string) (*types.ContinuousBackupsDescription, error) {
	output, err := c.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: &tableName})
	if err != nil {
		return nil, err
	}
	return output.ContinuousBackupsDescription, nil
}
