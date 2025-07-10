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
package com.alipay.application.service.rule.exposed;


import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.resource.exposed.QueryResourceService;
import com.alipay.application.service.rule.domain.RuleAgg;
import com.alipay.application.service.rule.domain.repo.RuleRepository;
import com.alipay.application.service.rule.domain.repo.factory.RuleExporter;
import com.alipay.application.service.rule.enums.RuleType;
import com.alipay.application.service.system.domain.enums.Status;
import com.alipay.common.utils.JsonMaskerUtils;
import com.alipay.dao.mapper.RuleMapper;
import com.alipay.dao.mapper.RuleTypeMapper;
import com.alipay.dao.po.DbCachePO;
import com.alipay.dao.po.RulePO;
import com.alipay.dao.po.RuleTypePO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.stereotype.Service;

import java.util.List;

/*
 *@title InitRuleServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/3/17 16:53
 */
@Slf4j
@Service
public class InitRuleServiceImpl implements InitRuleService {

    @Resource
    private RuleTypeMapper ruleTypeMapper;

    @Resource
    private RuleRepository ruleRepository;

    @Resource
    private RuleMapper ruleMapper;

    @Resource
    private GroupJoinService groupJoinService;

    @Resource
    private QueryResourceService queryResourceService;

    @Resource
    private DbCacheUtil dbCacheUtil;

    private static final String cacheKey = "rule::new::count";


    @Override
    public void initRuleType() {
        for (RuleType ruleType : RuleType.values()) {
            RuleTypePO ruleTypePO = ruleTypeMapper.findByTypeName(ruleType.getRuleType());
            if (ruleTypePO == null) {
                ruleTypePO = new RuleTypePO();
                ruleTypePO.setTypeName(ruleType.getRuleType());
                ruleTypePO.setStatus(Status.valid.name());
                ruleTypeMapper.insertSelective(ruleTypePO);
            }
        }
    }

    @Override
    public void loadRuleFromGithub(Boolean coverage) {
        List<RuleAgg> ruleAggs = ruleRepository.findRuleListFromGitHub();
        log.info("init rule form github, ruleAggs size: {}", ruleAggs.size());

        save(ruleAggs, coverage);

        dbCacheUtil.clear(cacheKey);
        dbCacheUtil.put(cacheKey, 0);
    }

    @Override
    public void loadRuleFromLocalFile() {
        List<RuleAgg> ruleAggs = ruleRepository.findRuleListFromLocalFile();
        log.info("init rule from local file, ruleAggs size: {}", ruleAggs.size());

        save(ruleAggs, false);
    }

    private void save(List<RuleAgg> ruleAggs, Boolean coverage) {
        for (RuleAgg ruleAgg : ruleAggs) {
            RulePO rulePO = ruleMapper.findOne(ruleAgg.getRuleCode());

            if (!coverage && rulePO != null) {
                // Already existing policies will not be updated yet
                log.info("rule code {} already exists, skip", ruleAgg.getRuleCode());
                continue;
            }

            // Save rules
            ruleRepository.saveOrgRule(ruleAgg);

            rulePO = ruleMapper.findOne(ruleAgg.getRuleCode());
            if (rulePO != null) {
                // Join the default rule group
                groupJoinService.joinDefaultGroup(rulePO.getId());
                // Save global variables
                if (CollectionUtils.isNotEmpty(ruleAgg.getGlobalVariables())) {
                    ruleRepository.relatedGlobalVariables(rulePO.getId(), ruleAgg.getGlobalVariables());
                }
            }
        }
    }

    @Override
    public String writeRule(List<Long> idList) {
        RuleExporter ruleExporter = new RuleExporter();
        List<RuleAgg> rules = ruleRepository.findByIdList(idList);
        for (RuleAgg rule : rules) {
            String resource = queryResourceService.queryExampleData(rule.getPlatform(), rule.getResourceType());
            try {
                rule.setExampleResourceData(JsonMaskerUtils.maskSensitiveData(resource));
            } catch (Exception e) {
                log.warn("Failed to mask sensitive data for rule code {}, skip", rule.getRuleCode());
            }
        }

        return ruleExporter.generateRulesFile(rules);
    }

    /**
     * Check if new rules exist
     */
    @Override
    public int checkExistNewRule() {
        DbCachePO dbCachePO = dbCacheUtil.get(cacheKey);
        if (dbCachePO != null) {
            return Integer.parseInt(dbCachePO.getValue());
        }

        int newRuleCount = ruleRepository.existNewRule();
        if (newRuleCount == 0) {
            return 0;
        }

        dbCacheUtil.put(cacheKey, newRuleCount);
        return newRuleCount;
    }
}
