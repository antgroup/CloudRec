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
import com.alipay.application.service.resource.enums.IdentitySecurityConfig;
import com.alipay.application.service.resource.enums.ResourceVisitType;
import com.alipay.application.service.resource.identitySecurity.model.ResourceAccessInfoDTO;
import com.alipay.application.service.resource.identitySecurity.model.ResourcePolicyInfoDTO;
import com.alipay.application.service.resource.identitySecurity.model.ResourceUserInfoDTO;
import com.alipay.dao.po.IdentitySecurityPO;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Date: 2025/4/28
 * Author: lz
 */
@Service
public class KsyunIamUserResourceParse implements CloudResourceInfoParser{

    @Override
    public IdentitySecurityPO parse(IdentitySecurityPO identitySecurityPO, String resourceInstance) {
        identitySecurityPO.setResourceTypeGroup(IdentitySecurityConfig.KINGSOFT_CLOUD_IAM_User.getResourceTypeGroup());
        identitySecurityPO.setPlatform(IdentitySecurityConfig.KINGSOFT_CLOUD_IAM_User.getPlatformType());
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
        if(jsonObject.get("User") != null){
            JSONObject userAttribute = jsonObject.getJSONObject("User");
            resourceUserInfoDTO.setUserName(userAttribute.getString("UserName"));
            resourceUserInfoDTO.setUserId(userAttribute.getString("UserId"));
            resourceUserInfoDTO.setCreateDate(userAttribute.getString("CreateDate"));
            resourceUserInfoDTO.setUpdateDate(userAttribute.getString("UpdateDate"));
            resourceUserInfoDTO.setEmail(userAttribute.getString("Email"));
        }
        return resourceUserInfoDTO;
    }

    @Override
    public List<ResourcePolicyInfoDTO> parsePolicyInfo(String resourceInstance) {
        return null;
    }

    @Override
    public List<ResourceAccessInfoDTO> parseAccessInfo(String resourceInstance) {
        JSONObject jsonObject = coverResourceInstanceStr(resourceInstance);
        List<ResourceAccessInfoDTO> resourceAccessInfoDTOS = new ArrayList<>();
        Object accessKeys = jsonObject.get("AccessKeys");
        if (accessKeys != null) {
            List<JSONObject> accessKeyList = JSON.parseArray(JSON.toJSONString(accessKeys), JSONObject.class);
            for (JSONObject accessKey : accessKeyList) {
                ResourceAccessInfoDTO resourceAccessInfoDTO = new ResourceAccessInfoDTO();
                resourceAccessInfoDTO.setAccessKeyId(accessKey.getString("AccessKeyId"));
                resourceAccessInfoDTOS.add(resourceAccessInfoDTO);
            }
        }
        return resourceAccessInfoDTOS;
    }

    @Override
    public List<String> getVisitTypes(String resourceInstance) {
        JSONObject jsonObject = coverResourceInstanceStr(resourceInstance);
        List<String> visitTypes = new ArrayList<>();
        Object accessKeys = jsonObject.get("AccessKeys");
        if (accessKeys != null) {
            List<JSONObject> accessKeyList = JSON.parseArray(JSON.toJSONString(accessKeys), JSONObject.class);
            if (accessKeyList.size() > 0) {
                visitTypes.add(ResourceVisitType.API.name());
            }
        }

        Object loginProfile = jsonObject.get("LoginProfile");
        if (loginProfile != null && BooleanUtils.isTrue(BooleanUtils.toBoolean(jsonObject.getString("ConsoleLogin")))) {  
            visitTypes.add(ResourceVisitType.Console.name());
        }
        
        return visitTypes;
    }

    @Override
    public List<String> parseTags(String resourceInstance, String ruleIds, String cloudAccountId, String resourceId) {
        return null;
    }


    private JSONObject coverResourceInstanceStr(String resourceInstanceStr) {
        if (StringUtils.isBlank(resourceInstanceStr)) {
            return new JSONObject();
        }
        return JSON.parseObject(resourceInstanceStr);
    }
}
