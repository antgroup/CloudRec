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

package main

import (
	alicloud "github.com/cloudrec/alicloud/platform"
	aws "github.com/cloudrec/aws/platform"
	baidu "github.com/cloudrec/baidu/platform"
	hws "github.com/cloudrec/hws/platform"
	ksyun "github.com/cloudrec/ksyun/platform"
	tencentcloud "github.com/cloudrec/tencent/platform"
	"github.com/core-sdk/schema"
)

func main() {

	// Support merging multiple cloud services into one process
	schema.RunExecutors(
		alicloud.GetPlatformConfig(),
		hws.GetPlatformConfig(),
		hws.GetPrivatePlatformConfig(),
		aws.GetPlatformConfig(),
		tencentcloud.GetPlatformConfig(),
		baidu.GetPlatformConfig(),
		// [7] ADD_NEW_CLOUD : Add new cloud provider config
		// template.GetPlatformConfig(),
		ksyun.GetPlatformConfig(),
	)

}
