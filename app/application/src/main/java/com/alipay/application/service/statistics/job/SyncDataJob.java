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
package com.alipay.application.service.statistics.job;


import com.alipay.application.service.account.cloud.DataProducer;
import com.alipay.common.constant.RuleGroupConstants;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.RuleGroupPO;
import com.alipay.dao.po.RuleGroupRelPO;
import com.alipay.dao.po.RulePO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/*
 *@title SyncDataJob
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/1/15 10:36
 */
@Slf4j
@Component
public class SyncDataJob {

    @Resource
    private RuleMapper ruleMapper;
    @Resource
    private RuleGroupRelMapper ruleGroupRelMapper;

    @Resource
    private RuleGroupMapper ruleGroupMapper;

    @Resource
    private List<DataProducer> dataProducers;

    public void syncCloudDataHandler() {
        dataProducers.forEach(dataProducer -> {
            log.info("Sync Data start, dataProducer: {}", dataProducer.getClass().getSimpleName());
            try {
                // 同步云上iam 统计 数据
                dataProducer.productIamStatisticsData();
            } catch (Exception e) {
                log.error("syncData error", e);
            }

            try {
                // 同步云上安全产品覆盖情况数据
                dataProducer.productSecurityProductStatisticsData();
            } catch (Exception e) {
                log.error("syncData error", e);
            }

            log.info("Sync iam data end, dataProducer: {}", dataProducer.getClass().getSimpleName());

        });
    }

    public void syncDefaultRuleGroup() {
        List<RulePO> list = ruleMapper.findAll();
        RuleGroupPO ruleGroupPO = ruleGroupMapper.findOne(RuleGroupConstants.DEFAULT_GROUP);
        for (RulePO rulePO : list) {
            RuleGroupRelPO ruleGroupRelPO = ruleGroupRelMapper.queryOne(rulePO.getId(), ruleGroupPO.getId());
            if (ruleGroupRelPO == null) {
                ruleGroupRelPO = new RuleGroupRelPO();
                ruleGroupRelPO.setRuleCode(rulePO.getRuleCode());
                ruleGroupRelPO.setRuleGroupId(ruleGroupPO.getId());
                ruleGroupRelPO.setRuleId(rulePO.getId());
                ruleGroupRelMapper.insertSelective(ruleGroupRelPO);
            }
        }
    }
}
