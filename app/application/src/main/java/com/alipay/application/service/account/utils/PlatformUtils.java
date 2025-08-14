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
package com.alipay.application.service.account.utils;


import com.alibaba.fastjson.JSON;
import com.alipay.application.service.account.cloud.alicloud.AliCloudCredential;
import com.alipay.application.service.account.cloud.alicloudprivate.AlicloudPrivateCredential;
import com.alipay.application.service.account.cloud.aws.AwsCredential;
import com.alipay.application.service.account.cloud.baidu.BaiduCredential;
import com.alipay.application.service.account.cloud.gcp.GcpCredential;
import com.alipay.application.service.account.cloud.hws.HwsCredential;
import com.alipay.application.service.account.cloud.hwsprivate.HwsPrivateCredential;
import com.alipay.application.service.account.cloud.ksyun.KsyunCredential;
import com.alipay.application.service.account.cloud.tencent.TencentCredential;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.common.constant.MarkConstants;
import com.alipay.common.enums.PlatformType;
import com.alipay.dao.mapper.ResourceMapper;
import com.alipay.dao.po.ResourcePO;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import software.amazon.awssdk.utils.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/*
 *@title PlatformUtils
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/12/25 10:21
 */
@Slf4j
public class PlatformUtils {

    private static final ResourceMapper resourceMapper = SpringUtils.getBean(ResourceMapper.class);

    /**
     * Obtain account platform related parameters
     */
    public static Map<String, String> getAccountCredentialsInfo(String platform, String credentialsJson) {

        Map<String, String> map = new HashMap<>();
        try {
            switch (platform) {
                case PlatformType.Enum.AWS:
                    AwsCredential awsCredential = new Gson().fromJson(credentialsJson, AwsCredential.class);
                    map.put("ak", awsCredential.getAk());
                    map.put("sk", awsCredential.getSk());
                    break;
                case PlatformType.Enum.ALI_CLOUD:
                    AliCloudCredential aliyunCredential = new Gson().fromJson(credentialsJson, AliCloudCredential.class);
                    map.put("ak", aliyunCredential.getAk());
                    map.put("sk", aliyunCredential.getSk());
                    break;
                case PlatformType.Enum.HUAWEI_CLOUD:
                    HwsCredential hwsCredential = new Gson().fromJson(credentialsJson, HwsCredential.class);
                    map.put("ak", hwsCredential.getAk());
                    map.put("sk", hwsCredential.getSk());
                    break;
                case PlatformType.Enum.TENCENT_CLOUD:
                    TencentCredential tencentCredential = new Gson().fromJson(credentialsJson, TencentCredential.class);
                    map.put("ak", tencentCredential.getAk());
                    map.put("sk", tencentCredential.getSk());
                    break;
                case PlatformType.Enum.GCP:
                    GcpCredential gcpCredential = new Gson().fromJson(credentialsJson, GcpCredential.class);
                    map.put("credential", gcpCredential.getCredential());
                    break;
                case PlatformType.Enum.BAIDU_CLOUD:
                    BaiduCredential baiduCredential = new Gson().fromJson(credentialsJson, BaiduCredential.class);
                    map.put("ak", baiduCredential.getAk());
                    map.put("sk", baiduCredential.getSk());
                    break;
                case PlatformType.Enum.ALI_CLOUD_PRIVATE:
                    AlicloudPrivateCredential alicloudPrivateCredential = new Gson().fromJson(credentialsJson, AlicloudPrivateCredential.class);
                    map.put("ak", alicloudPrivateCredential.getAk());
                    map.put("sk", alicloudPrivateCredential.getSk());
                    map.put("endpoint", alicloudPrivateCredential.getEndpoint());
                    map.put("regionId", alicloudPrivateCredential.getRegionId());
                    break;
                case PlatformType.Enum.HUAWEI_CLOUD_PRIVATE:
                    HwsPrivateCredential hwsPrivateCredential = new Gson().fromJson(credentialsJson, HwsPrivateCredential.class);
                    map.put("ak", hwsPrivateCredential.getAk());
                    map.put("sk", hwsPrivateCredential.getSk());
                    map.put("regionId", hwsPrivateCredential.getRegionId());
                    map.put("projectId", hwsPrivateCredential.getProjectId());
                    map.put("iamEndpoint", hwsPrivateCredential.getIamEndpoint());
                    map.put("ecsEndpoint", hwsPrivateCredential.getEcsEndpoint());
                    map.put("elbEndpoint", hwsPrivateCredential.getElbEndpoint());
                    map.put("evsEndpoint", hwsPrivateCredential.getEvsEndpoint());
                    map.put("vpcEndpoint", hwsPrivateCredential.getVpcEndpoint());
                    map.put("obsEndpoint", hwsPrivateCredential.getObsEndpoint());
                    break;

                case PlatformType.Enum.KINGSOFT_CLOUD:
                    KsyunCredential ksyunCredential = new Gson().fromJson(credentialsJson, KsyunCredential.class);
                    map.put("ak", ksyunCredential.getAk());
                    map.put("sk", ksyunCredential.getSk());
                    break;
                //  case PlatformType.Enum.My_Cloud_Provider:
                // [3] ADD_NEW_CLOUD : To adapt the logic of parsing authentication information, you need to add a class corresponding to the cloud platform authentication information
                default:
                    throw new IllegalStateException("Unexpected value: " + platform);
            }
        } catch (Exception e) {
            log.error("decryptCredentialsJson error", e);
        }

        map.put("platform", platform);
        return map;
    }

   /**
     * Decryption
     *
     * @param credentialsJson authentication information json
     * @return Authentication information map after removing sensitive information
     */
    public static String decryptCredentialsJson(String credentialsJson) {
        return AESEncryptionUtils.decrypt(credentialsJson);
    }

    public static Map<String, String> ignoreSensitiveInfo(Map<String, String> map) {
        String platform = map.get("platform");
        switch (platform) {
            case PlatformType.Enum.GCP:
                try {
                    Map credentialMap = JSON.parseObject(map.get("credential"), Map.class);
                    credentialMap.put("private_key_id", MarkConstants.marks);
                    credentialMap.put("private_key", MarkConstants.marks);
                    map.put("credential", JSON.toJSONString(credentialMap));
                } catch (Exception e) {
                    log.error("credential is not json", e);
                }
                break;
            default:
                if (map.containsKey("sk")) {
                    map.put("sk", MarkConstants.marks);
                }
        }

        return map;
    }

    public static void checkCredentialsJson(String credentialsJson) {
        if (StringUtils.isEmpty(credentialsJson)) {
            throw new IllegalArgumentException("credentialsJson is empty");
        }

        if (credentialsJson.contains(MarkConstants.mark)) {
            throw new IllegalArgumentException("please enter the correct key");
        }
    }

    public static Cache<String, List<String>> cache() {
        return CacheBuilder.newBuilder()
                .maximumSize(10)
                .expireAfterWrite(60, TimeUnit.MINUTES)
                .build();
    }

    public static List<String> getResourceType(String platform) {
        // find from cache
        List<String> resourceTypeList = cache().getIfPresent(platform);
        if (resourceTypeList != null) {
            return resourceTypeList;
        }

        List<ResourcePO> list = resourceMapper.findByPlatform(platform);
        if (CollectionUtils.isEmpty(list)){
            log.info("getResourceType is empty, platform: {}", platform);
            cache().put(platform, new ArrayList<>());
            return new ArrayList<>();
        }
        List<String> typeList = list.stream().map(ResourcePO::getResourceType).toList();
        cache().put(platform, typeList);
        return typeList;
    }
}
