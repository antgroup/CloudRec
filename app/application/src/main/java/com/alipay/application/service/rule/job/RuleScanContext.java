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


import com.alipay.application.service.rule.domain.GlobalVariable;
import com.alipay.application.service.rule.domain.RuleAgg;
import com.alipay.application.service.rule.domain.repo.OpaRepository;
import com.alipay.application.service.rule.domain.repo.RuleRepository;
import com.alipay.application.service.system.domain.enums.Status;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import com.alibaba.fastjson.JSON;

import java.util.List;

/*
 *@title RuleContext
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/3/11 23:09
 */
@Slf4j
@Component
public class RuleScanContext {

    @Resource
    private RuleRepository ruleRepository;

    @Resource
    private OpaRepository opaRepository;

    /**
     * Initialize the rego policy and global variables of the rule to avoid frequent performance-consuming creation
     */
    @EventListener
    private void init(ApplicationReadyEvent event) {
        try {
            List<RuleAgg> list = ruleRepository.findAll();
            list.forEach(this::load);
            log.info("Rules loaded after application started.");
        } catch (Exception e) {
            log.error("Rules loaded after application started failed.", e);
        }
    }

    public void loadByRuleId(Long ruleId) {
        RuleAgg ruleAgg = ruleRepository.findByRuleId(ruleId);
        load(ruleAgg);
    }

    public void loadByGroupId(Long groupId) {
        List<RuleAgg> list = ruleRepository.findByGroupId(groupId, Status.valid.name());
        list.forEach(this::load);
    }

    private void load(RuleAgg ruleAgg) {
        if (StringUtils.isEmpty(ruleAgg.getRegoPath()) || StringUtils.isEmpty(ruleAgg.getRegoPolicy())) {
            log.warn("The Rego policy is empty,ruleId:{}, ruleCode:{},ruleName:{}", ruleAgg.getId(), ruleAgg.getRuleCode(), ruleAgg.getRuleName());
            return;
        }
        opaRepository.createOrUpdatePolicy(ruleAgg.getRegoPath(), ruleAgg.getRegoPolicy());
        if (CollectionUtils.isNotEmpty(ruleAgg.getGlobalVariables())) {
            for (GlobalVariable globalVariable : ruleAgg.getGlobalVariables()) {
                opaRepository.upsertData(globalVariable.getPath(), JSON.parse(globalVariable.getData()));
            }
        }
    }

    private static final ThreadLocal<RuleAgg> CURRENT_RULE = new ThreadLocal<>();

    public static void setCurrentRule(RuleAgg ruleAgg) {
        CURRENT_RULE.set(ruleAgg);
    }

    public static RuleAgg getCurrentRule() {
        return CURRENT_RULE.get();
    }

    public static void clear() {
        CURRENT_RULE.remove();
    }

}
