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
package com.alipay.application.service.resource.identitySecurity;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alipay.application.service.common.SystemConfigService;
import com.alipay.application.service.resource.enums.IdentitySecurityConfig;
import com.alipay.application.service.resource.enums.IdentityTagConfig;
import com.alipay.application.service.resource.enums.ResourceVisitType;
import com.alipay.application.service.resource.identitySecurity.model.ResourceAccessInfoDTO;
import com.alipay.application.service.resource.identitySecurity.model.ResourcePolicyInfoDTO;
import com.alipay.application.service.resource.identitySecurity.model.ResourceUserInfoDTO;
import com.alipay.common.enums.PlatformType;
import com.alipay.common.utils.DateUtil;
import com.alipay.dao.mapper.CloudResourceInstanceMapper;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.alipay.dao.po.IdentitySecurityPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Date: 2025/4/18
 * Author: lz
 * desc:
 */
@Slf4j
@Component
public class AliRamUserResourceParse implements CloudResourceInfoParser {

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    public static final String ACCOUNT_RESOURCE_TYPE = "Account";

    @Resource
    private SystemConfigService systemConfigService;


    @Override
    public IdentitySecurityPO parse(IdentitySecurityPO identitySecurityPO, String resourceInstance) {
        identitySecurityPO.setResourceTypeGroup(IdentitySecurityConfig.ALI_CLOUD_RAM_User.getResourceTypeGroup());
        identitySecurityPO.setPlatform(IdentitySecurityConfig.ALI_CLOUD_RAM_User.getPlatformType());
        identitySecurityPO.setAccessType(String.join(",", getVisitTypes(resourceInstance)));
        identitySecurityPO.setAccessInfos(JSON.toJSONString(parseAccessInfo(resourceInstance)));
        identitySecurityPO.setUserInfo(JSON.toJSONString(parseUserInfo(resourceInstance)));
        identitySecurityPO.setPolicies(JSON.toJSONString(parsePolicyInfo(resourceInstance)));
        return identitySecurityPO;
    }

    @Override
    public ResourceUserInfoDTO parseUserInfo(String resourceInstance) {
        JSONObject jsonObject = coverResourceInstanceStr(resourceInstance);
        ResourceUserInfoDTO resourceUserInfoDTO = new ResourceUserInfoDTO();
        if (jsonObject.get("UserDetail") != null) {
            JSONObject userDetailJson = jsonObject.getJSONObject("UserDetail");
            resourceUserInfoDTO.setUserName(userDetailJson.getString("UserName") + "/" + userDetailJson.getString("DisplayName"));
            resourceUserInfoDTO.setUserId(userDetailJson.getString("UserId"));
            resourceUserInfoDTO.setCreateDate(DateUtil.formatISODateTime(userDetailJson.getString("CreateDate")));
            resourceUserInfoDTO.setUpdateDate(DateUtil.formatISODateTime(userDetailJson.getString("UpdateDate")));
            resourceUserInfoDTO.setEmail(userDetailJson.getString("Email"));
            resourceUserInfoDTO.setLastLoginDate(userDetailJson.getString("LastLoginDate"));
            resourceUserInfoDTO.setPlatform(PlatformType.ALI_CLOUD.getPlatform());
        }
        if (jsonObject.get("LoginProfile") != null) {
            JSONObject loginProfile = JSON.parseObject(jsonObject.getString("LoginProfile"));
            resourceUserInfoDTO.setMFAStatus(BooleanUtils.toBoolean(loginProfile.getString("MFABindRequired")));
        }
        resourceUserInfoDTO.setPlatform(PlatformType.ALI_CLOUD.getPlatform());
        return resourceUserInfoDTO;
    }

    @Override
    public List<ResourcePolicyInfoDTO> parsePolicyInfo(String resourceInstance) {
        JSONObject jsonObject = coverResourceInstanceStr(resourceInstance);
        List<ResourcePolicyInfoDTO> resourcePolicyInfoDTOS = new ArrayList<>();
        Object resourcepolicies = jsonObject.get("Policies");
        if (resourcepolicies != null) {
            List<JSONObject> resourcePolicyList = JSON.parseArray(JSON.toJSONString(resourcepolicies), JSONObject.class);
            for (JSONObject completePolicys : resourcePolicyList) {
                ResourcePolicyInfoDTO resourcePolicyInfoDTO = new ResourcePolicyInfoDTO();
                if (completePolicys.get("Policy") != null) {
                    JSONObject policy = JSON.parseObject(completePolicys.getString("Policy"));
                    resourcePolicyInfoDTO.setPolicyName(policy.getString("PolicyName"));
                    resourcePolicyInfoDTO.setPolicyType(policy.getString("PolicyType"));
                    resourcePolicyInfoDTO.setDescription(policy.getString("Description"));
                }
                if (completePolicys.get("DefaultPolicyVersion") != null) {
                    JSONObject defaultPolicyVersion = JSON.parseObject(completePolicys.getString("DefaultPolicyVersion"));
                    resourcePolicyInfoDTO.setPolicyDocument(defaultPolicyVersion.getString("PolicyDocument"));
                }
                if (completePolicys.get("Source") != null){
                    resourcePolicyInfoDTO.setSource(completePolicys.getString("Source"));
                }
                resourcePolicyInfoDTOS.add(resourcePolicyInfoDTO);
            }
        }
        return resourcePolicyInfoDTOS;
    }

    @Override
    public List<ResourceAccessInfoDTO> parseAccessInfo(String resourceInstance) {
        JSONObject jsonObject = coverResourceInstanceStr(resourceInstance);
        List<ResourceAccessInfoDTO> resourceAccessInfoDTOS = new ArrayList<>();
        Object accessKeys = jsonObject.get("AccessKeys");
        if (accessKeys != null) {
            List<String> visitTypes = getVisitTypes(resourceInstance);
            List<JSONObject> accessKeyList = JSON.parseArray(JSON.toJSONString(accessKeys), JSONObject.class);
            for (JSONObject accessKey : accessKeyList) {
                ResourceAccessInfoDTO resourceAccessInfoDTO = new ResourceAccessInfoDTO();
                resourceAccessInfoDTO.setAccessKeyId(accessKey.getJSONObject("AccessKey").getString("AccessKeyId"));
//                resourceAccessInfoDTO.setStatus(accessKey.getJSONObject("AccessKey").getString("Status"));
                resourceAccessInfoDTO.setVisitTypes(visitTypes);
                resourceAccessInfoDTOS.add(resourceAccessInfoDTO);
            }
        }
        return resourceAccessInfoDTOS;
    }

    @Override
    public List<String> getVisitTypes(String resourceInstance) {
        JSONObject jsonObject = coverResourceInstanceStr(resourceInstance);
        List<String> visitTypes = new ArrayList<>();
        if (Objects.nonNull(jsonObject) && BooleanUtils.isTrue(BooleanUtils.toBoolean(jsonObject.getString("ConsoleLogin")))) {
            visitTypes.add(ResourceVisitType.Console.name());
        }
        if (Objects.nonNull(jsonObject) && BooleanUtils.isTrue(BooleanUtils.toBoolean(jsonObject.getString("ExistAccessKey")))) {
            visitTypes.add(ResourceVisitType.API.name());
        }
        return visitTypes;
    }

    @Override
    public List<String> parseTags(String resourceInstance, String ruleIds, String cloudAccountId, String resourceId) {

        List<String> tagList = new ArrayList<>();
        JSONObject jsonObject = coverResourceInstanceStr(resourceInstance);
        //（常规）ConsoleLoginMethod：[SSO/Password]
        CloudResourceInstancePO cloudResourceInstancePO = cloudResourceInstanceMapper.findOne(PlatformType.ALI_CLOUD.getPlatform(), ACCOUNT_RESOURCE_TYPE, cloudAccountId, resourceId);
        if (Objects.nonNull(cloudResourceInstancePO)) {
            String instance = cloudResourceInstancePO.getInstance();
            JSONObject accountJsonObject = coverResourceInstanceStr(instance);
            if (Objects.nonNull(accountJsonObject.getJSONObject("UserSsoSettings"))) {
                JSONObject userSsoSettings = accountJsonObject.getJSONObject("UserSsoSettings");
                if (BooleanUtils.isTrue(userSsoSettings.getBoolean("SsoEnabled"))) {
                    tagList.add(IdentityTagConfig.ConsoleLoginMethod_SSO.getTagName());
                }
            }
        }
        if (!tagList.contains(IdentityTagConfig.ConsoleLoginMethod_SSO.getTagName())
                && BooleanUtils.isTrue(BooleanUtils.toBoolean(jsonObject.getString("ConsoleLogin")))) {
            tagList.add(IdentityTagConfig.ConsoleLoginMethod_Password.getTagName());
        }


        //（常规）MFA：[enabled/disabled]
        boolean mfaBindRequired = false;
        if (jsonObject.get("LoginProfile") != null) {
            JSONObject loginProfile = JSON.parseObject(jsonObject.getString("LoginProfile"));
            mfaBindRequired = BooleanUtils.toBoolean(loginProfile.getString("MFABindRequired"));
        }
        if (BooleanUtils.isTrue(BooleanUtils.toBoolean(jsonObject.getString("ConsoleLogin"))) && !mfaBindRequired) {
            tagList.add(IdentityTagConfig.MFA.getTagName());
        }

        //（风险）敏感权限无ACL: [true/false]
        if (compareStrArr(systemConfigService.getAliNoAclRuleIds(), ruleIds)) {
            tagList.add(IdentityTagConfig.NO_ACL.getTagName());
        }

        //（风险）INACTIVE: [true/ false]
        if (compareStrArr(systemConfigService.getAliInactiveRuleIds(), ruleIds)) {
            tagList.add(IdentityTagConfig.INACTIVE.getTagName());
        }

        return tagList;
    }


    private JSONObject coverResourceInstanceStr(String resourceInstanceStr) {
        if (StringUtils.isBlank(resourceInstanceStr)) {
            return new JSONObject();
        }
        return JSON.parseObject(resourceInstanceStr);
    }

    /**
     * 比较字符串数组str2 是否 包含在 str1 中
     *
     * @param str1
     * @param str2
     * @return
     */
    private boolean compareStrArr(String str1, String str2) {
        if (StringUtils.isBlank(str1) || StringUtils.isBlank(str2)) {
            return false;
        }
        try {
            Set<String> set1 = new HashSet<>(Arrays.asList(str1.split(",")));
            Set<String> set2 = new HashSet<>(Arrays.asList(str2.split(",")));
            // 检查 set2 是否为 set1 的子集
            return set1.containsAll(set2);
        } catch (Exception e) {
            log.error("AliRamUserResourceParse compareStrArr error", e);
        }
        return false;
    }

}

