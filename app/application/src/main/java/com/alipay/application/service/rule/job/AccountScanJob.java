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

import com.alipay.application.service.rule.domain.RuleAgg;
import com.alipay.application.service.rule.domain.repo.RuleRepository;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.dao.mapper.CloudAccountMapper;
import com.alipay.dao.po.CloudAccountPO;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.concurrent.TimeUnit;

/*
 *@title ScanServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/18 09:12
 */
@Slf4j
@Service
public class AccountScanJob {

    @Resource
    private ScanServiceImpl scanService;
    @Resource
    private CloudAccountMapper cloudAccountMapper;
    @Resource
    private RuleRepository ruleRepository;
    @Resource
    private WhitedConfigContext whitedConfigContext;
    @Resource
    private TenantRepository tenantRepository;

    private final Cache<String, List<RuleAgg>> ruleCache = CacheBuilder.newBuilder()
            .maximumSize(10)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();

    public void scanByCloudAccountId(String cloudAccountId) {
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (cloudAccountPO == null) {
            return;
        }

        // load rule form cache
        List<RuleAgg> ruleAggList;
        synchronized (this) {
            List<RuleAgg> cacheRuleAggList = ruleCache.getIfPresent(cloudAccountPO.getPlatform());
            if (!CollectionUtils.isEmpty(cacheRuleAggList)) {
                ruleAggList = cacheRuleAggList;
            } else {
                // load rule from db
                ruleAggList = ruleRepository.findAll(cloudAccountPO.getPlatform());
                ruleCache.put(cloudAccountPO.getPlatform(), ruleAggList);
                // load whited config
                whitedConfigContext.refreshWhitedConfigs();
            }
        }

        try {
            long startTime = System.currentTimeMillis();
            log.info("scanByCloudAccountId start, cloudAccountId:{}, platform:{} start", cloudAccountId, cloudAccountPO.getPlatform());
            for (RuleAgg ruleAgg : ruleAggList) {
                if (ruleAgg.getIsRunning() == 1) {
                    log.info("scanByCloudAccountId skip, cloudAccountId:{}, platform:{}, ruleCode:{}", cloudAccountId, cloudAccountPO.getPlatform(), ruleAgg.getRuleCode());
                    continue;
                }
                log.info("scanByCloudAccountId start, cloudAccountId:{}, platform:{}, ruleCode:{}", cloudAccountId, cloudAccountPO.getPlatform(), ruleAgg.getRuleCode());
                scanService.scanByRule(ruleAgg, cloudAccountPO, tenantRepository.isDefaultRule(ruleAgg.getRuleCode()));
                log.info("scanByCloudAccountId end, cloudAccountId:{}, platform:{}, ruleCode:{} end", cloudAccountId, cloudAccountPO.getPlatform(), ruleAgg.getRuleCode());
            }
            log.info("scanByCloudAccountId end, cloudAccountId:{}, platform:{} end, spend time:{}", cloudAccountId, cloudAccountPO.getPlatform(), System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            log.error("scanByCloudAccountId error, cloudAccountId:{}", cloudAccountId, e);
        } finally {
            // clear whited config cache
            whitedConfigContext.clear();
        }
    }
}
