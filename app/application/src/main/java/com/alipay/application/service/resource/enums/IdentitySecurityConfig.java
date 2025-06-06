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
package com.alipay.application.service.resource.enums;

import com.alipay.common.enums.PlatformType;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

/**
 * Date: 2025/4/18
 * Author: lz
 */
@Getter
@AllArgsConstructor
public enum IdentitySecurityConfig {

    ALI_CLOUD_RAM_User(PlatformType.Enum.ALI_CLOUD, "RAM User", "User"),
    HUAWEI_CLOUD_IAM_User(PlatformType.Enum.HUAWEI_CLOUD, "IAM User", "User"),
    GCP_IAM_ServiceAccount(PlatformType.Enum.GCP, "IAM ServiceAccount","Service Account"),
    KINGSOFT_CLOUD_IAM_User(PlatformType.Enum.KINGSOFT_CLOUD, "IAM User","User"),
    ;

    private String platformType;

    private String resourceType;

    private String resourceTypeGroup;


    public static List<String> getSupportedPlatformList() {
        List<String> platformTypes = new ArrayList<>();
        for (IdentitySecurityConfig rule : IdentitySecurityConfig.values()) {
            platformTypes.add(rule.getPlatformType());
        }
        return platformTypes;
    }

    public static List<String> getSupportedResourceTypeList() {
        List<String> resourceTypes = new ArrayList<>();
        for (IdentitySecurityConfig rule : IdentitySecurityConfig.values()) {
            resourceTypes.add(rule.getResourceType());
        }
        return resourceTypes;
    }

    public static List<String> getResourceTypeByPlatform(String platformType) {
        List<String> resourceTypes = new ArrayList<>();
        for (IdentitySecurityConfig rule : IdentitySecurityConfig.values()) {
            if(rule.getPlatformType().equals(platformType)) {
                resourceTypes.add(rule.getResourceType());
            }
        }
        return resourceTypes;
    }

    public static List<String> getResourceTypeByPlatformList(List<String> platformTypeList){
        List<String> resourceTypes = new ArrayList<>();
        for (String platformType : platformTypeList) {
            for (IdentitySecurityConfig rule : IdentitySecurityConfig.values()) {
                if(rule.getPlatformType().equals(platformType)) {
                    resourceTypes.add(rule.getResourceType());
                }
            }
        }
        return resourceTypes;
    }

}
