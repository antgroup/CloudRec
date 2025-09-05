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
package com.alipay.application.service.rule;

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.rule.domain.repo.OpaRepository;
import com.alipay.application.share.request.rule.WhitedScanInputDataDTO;
import com.alipay.common.constant.OpaFlagConstants;
import com.alipay.dao.po.CloudAccountPO;
import com.alipay.dao.po.CloudResourceInstancePO;
import com.alipay.dao.po.RuleScanResultPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Date: 2025/3/18
 * Author: lz
 * Description: 使用rego模式扫描规则
 */
@Slf4j
@Component
public class WhitedRegoMatcher {

    @Resource
    private OpaRepository opaRepository;

    @Resource
    private WhitedExampleDataComponent whitedExampleDataComponent;


    public boolean executeRegoMatch(String regoContent,String whitedRuleConfigId, WhitedScanInputDataDTO whitedScanInputDataDTO){

        Map<String, Object> result;
        if(StringUtils.isEmpty(whitedRuleConfigId)){
            String regoPath = opaRepository.findPackage(regoContent);
            opaRepository.createOrUpdatePolicy(regoPath, regoContent);
            result = opaRepository.callOpa(regoPath, regoContent, JSON.toJSONString(whitedScanInputDataDTO));
        }else {
            String regoPath = opaRepository.findWhitedConfigPackage(regoContent, whitedRuleConfigId);
            result = opaRepository.callOpa(regoPath, regoContent, JSON.toJSONString(whitedScanInputDataDTO));
        }

        if (result == null) {
            log.warn("Execute rule failed");
            return false;
        }

        Object o = result.get(OpaFlagConstants.WHITED_MARKING);
        if (o == null) {
            return false;
        }
        if (o instanceof Boolean && (Boolean) o) {
            return (Boolean) o;
        }
        return false;
    }

    public boolean executeRegoMatch(String regoContent,String whitedRuleConfigId, RuleScanResultPO ruleScanResultPO, CloudAccountPO cloudAccountPO, CloudResourceInstancePO resourceInstance){
        WhitedScanInputDataDTO whitedScanInputDataDTO = whitedExampleDataComponent.buildWhitedExampleDataResultDTO(ruleScanResultPO, cloudAccountPO, resourceInstance);
        return executeRegoMatch(regoContent, whitedRuleConfigId, whitedScanInputDataDTO);
    }
}
