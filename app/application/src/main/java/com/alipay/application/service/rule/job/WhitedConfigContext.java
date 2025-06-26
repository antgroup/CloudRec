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
package com.alipay.application.service.rule.job;


import com.alipay.application.service.rule.domain.repo.OpaRepository;
import com.alipay.common.enums.WhitedRuleTypeEnum;
import com.alipay.dao.dto.QueryWhitedRuleDTO;
import com.alipay.dao.mapper.WhitedRuleConfigMapper;
import com.alipay.dao.po.WhitedRuleConfigPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Date: 2025/3/31
 * Author: lz
 */
@Slf4j
@Component
public class WhitedConfigContext {

    @Resource
    private WhitedRuleConfigMapper whitedRuleConfigMapper;

    @Resource
    private OpaRepository opaRepository;

    private static final ThreadLocal<List<WhitedRuleConfigPO>> WHITED_CONFIG_THREAD_LOCAL_CACHE = new ThreadLocal<>();

    public void loadEnableWhitedConfigs() {
        QueryWhitedRuleDTO dto = new QueryWhitedRuleDTO();
        dto.setEnable(1);
        dto.setSize(1000);
        dto.setRuleType(WhitedRuleTypeEnum.REGO.name());
        List<WhitedRuleConfigPO> list = whitedRuleConfigMapper.list(dto);
        for (WhitedRuleConfigPO whitedRuleConfigPO : list) {
            String regoContent = whitedRuleConfigPO.getRegoContent();
            String regoPath = opaRepository.findWhitedConfigPackage(regoContent,whitedRuleConfigPO.getId().toString());
            String newrRgoPolicy = regoContent.replaceFirst("(?<=package )\\S+", regoPath);
            opaRepository.createOrUpdatePolicy(regoPath, newrRgoPolicy);
        }
    }

    protected void initWhitedConfigCache() {
        List<WhitedRuleConfigPO> whitedRuleConfigPOList = new ArrayList<>();
        QueryWhitedRuleDTO queryWhitedRuleDTO = new QueryWhitedRuleDTO();
        queryWhitedRuleDTO.setEnable(1);

        int count = whitedRuleConfigMapper.count(queryWhitedRuleDTO);
        if (count == 0) {
            WHITED_CONFIG_THREAD_LOCAL_CACHE.set(new ArrayList<>());
            return;
        }
        List<WhitedRuleConfigPO> whitedRuleConfigPOS = WHITED_CONFIG_THREAD_LOCAL_CACHE.get();
        if (CollectionUtils.isEmpty(whitedRuleConfigPOS) || whitedRuleConfigPOS.size() != count) {
            WHITED_CONFIG_THREAD_LOCAL_CACHE.remove();
        }

        queryWhitedRuleDTO.setSize(100);
        int page = 1;
        while (true) {
            queryWhitedRuleDTO.setPage(page);
            queryWhitedRuleDTO.setOffset();
            List<WhitedRuleConfigPO> dataList = whitedRuleConfigMapper.list(queryWhitedRuleDTO);
            if (CollectionUtils.isEmpty(dataList)) {
                break;
            }
            whitedRuleConfigPOList.addAll(dataList);
            page++;
        }
        WHITED_CONFIG_THREAD_LOCAL_CACHE.set(whitedRuleConfigPOList);
    }

    protected void clear() {
        WHITED_CONFIG_THREAD_LOCAL_CACHE.remove();
    }

    // get
    protected List<WhitedRuleConfigPO> get() {
        return WHITED_CONFIG_THREAD_LOCAL_CACHE.get();
    }

}
