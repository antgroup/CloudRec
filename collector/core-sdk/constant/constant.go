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

package constant

const (
	SuccessCode = 200
	FailureCode = 500
)

const DefaultPage = 1
const DefaultPageSize = 50

// MaxResourcePushCount Maximum number of pushes in a single session
const MaxResourcePushCount = 50

// TimeOut 30s
const TimeOut = 30

type contextKey string

// DefaultCloudAccountMaxConcurrent Default number of concurrent collection tasks
const DefaultCloudAccountMaxConcurrent = 4

const (
	StartTime       contextKey = "StartTime"
	EndTime         contextKey = "EndTime"
	Duration        contextKey = "Duration"
	Platform        contextKey = "Platform"
	CloudAccountId  contextKey = "CloudAccountId"
	RegionId        contextKey = "RegionId"
	ResourceType    contextKey = "ResourceType"
	TraceId         contextKey = "TraceId"
	CollectRecordId contextKey = "CollectRecordId"
)
