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

type PlatformType string

// platform type. If you need to add a platform, add an enumeration here
const (
	HuaweiCloud         PlatformType = "HUAWEI_CLOUD"         // 华为云
	HuaweiCloudPrivate  PlatformType = "HUAWEI_CLOUD_PRIVATE" // 华为云专有云
	AlibabaCloudPrivate PlatformType = "ALI_CLOUD_PRIVATE"    // 阿里专有云
	AlibabaCloud        PlatformType = "ALI_CLOUD"            // 阿里云
	TencentCloud        PlatformType = "TENCENT_CLOUD"        // 腾讯云
	BaiduCloud          PlatformType = "BAIDU_CLOUD"          // 百度云
	AWS                 PlatformType = "AWS"                  // AWS
	GCP                 PlatformType = "GCP"                  // 谷歌云
	IBM                 PlatformType = "AZURE"                // AZURE
	// [1] ADD_NEW_CLOUD : Add a new cloud provider enum.
	//MyCloudProvider PlatformType = "My_Cloud_Provider"
	KingsoftCloud PlatformType = "KINGSOFT_CLOUD"
)

type PlatformDescription map[PlatformType]string

// PlatformDescriptions Description. If you need to add an asset, add an enumeration here
var platformDescriptions = PlatformDescription{
	HuaweiCloud:         "华为云",
	HuaweiCloudPrivate:  "华为专有云",
	AlibabaCloudPrivate: "阿里专有云",
	AlibabaCloud:        "阿里云",
	TencentCloud:        "腾讯云",
	BaiduCloud:          "百度云",
	AWS:                 "AWS",
	GCP:                 "GCP",
	IBM:                 "AZURE",
	KingsoftCloud:       "金山云",
}

// GetPlatformName Get the name of the platform
func GetPlatformName(platform string) string {
	s := platformDescriptions[PlatformType(platform)]
	return s
}
