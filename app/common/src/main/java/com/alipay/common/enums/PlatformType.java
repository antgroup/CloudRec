/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.common.enums;

/*
 *@title PlatformType
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/8/7 13:52
 */
public enum PlatformType {


    UNKNOWN(Enum.UNKNOWN, "未知", "UNKNOWN"),
    HUAWEI_CLOUD(Enum.HUAWEI_CLOUD, "华为云", "Huawei Cloud"),

    HUAWEI_CLOUD_PRIVATE(Enum.HUAWEI_CLOUD_PRIVATE, "华为专有云", "Huawei Private Cloud"),

    ALI_CLOUD_PRIVATE(Enum.ALI_CLOUD_PRIVATE, "阿里专有云", "Alibaba Private Cloud"),

    ALI_CLOUD(Enum.ALI_CLOUD, "阿里云", "Alibaba Cloud"),

    TENCENT_CLOUD(Enum.TENCENT_CLOUD, "腾讯云", "Tencent Cloud"),

    BAIDU_CLOUD(Enum.BAIDU_CLOUD, "百度云", "Baidu Cloud"),

    AWS(Enum.AWS, "AWS", "AWS"),

    GCP(Enum.GCP, "GCP", "GCP"),

    AZURE(Enum.AZURE, "AZURE", "AZURE"),
    // [2] ADD_NEW_CLOUD : Add a new cloud provider.
    // MyCloudProvider(Enum.MyCloudProvider, "我的云", "My Cloud Provider");

    KINGSOFT_CLOUD(Enum.KINGSOFT_CLOUD, "金山云", "Kingsoft Cloud");

    private String platform;
    private String cnName;

    private String enName;

    PlatformType(String platform, String cnName, String enName) {
        this.platform = platform;
        this.cnName = cnName;
        this.enName = enName;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getCnName() {
        return cnName;
    }

    public void setCnName(String cnName) {
        this.cnName = cnName;
    }

    public String getEnName() {
        return enName;
    }

    public void setEnName(String enName) {
        this.enName = enName;
    }

    /**
     * 获取平台类型
     *
     * @param platform 平台
     * @return 平台类型
     */
    public static PlatformType getPlatformType(String platform) {
        for (PlatformType platformType : PlatformType.values()) {
            if (platformType.name().equals(platform)) {
                return platformType;
            }
        }
        return UNKNOWN;
    }

    public static class Enum {
        public static final String UNKNOWN = "UNKNOWN";
        public static final String HUAWEI_CLOUD = "HUAWEI_CLOUD";
        public static final String HUAWEI_CLOUD_PRIVATE = "HUAWEI_CLOUD_PRIVATE";
        public static final String ALI_CLOUD_PRIVATE = "ALI_CLOUD_PRIVATE";
        public static final String ALI_CLOUD = "ALI_CLOUD";
        public static final String TENCENT_CLOUD = "TENCENT_CLOUD";
        public static final String BAIDU_CLOUD = "BAIDU_CLOUD";
        public static final String AWS = "AWS";
        public static final String GCP = "GCP";
        public static final String AZURE = "AZURE";
        // [1] ADD_NEW_CLOUD : Add a new cloud provider enum.
        // public static final String MyCloudProvider = "My_Cloud_Provider";
        public static final String KINGSOFT_CLOUD = "KINGSOFT_CLOUD";
    }
}
