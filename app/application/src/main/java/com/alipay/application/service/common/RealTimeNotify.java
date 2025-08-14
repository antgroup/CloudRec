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
package com.alipay.application.service.common;

import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.common.enums.Status;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.dto.SubscriptionDTO;
import com.alipay.dao.po.*;
import com.alipay.application.service.common.enums.SubscriptionType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/*
 *@title RealTimeNotify
 *@description Real-time notification
 *@author jietian
 *@version 1.0
 *@create 2024/9/26 18:15
 */

@Slf4j
@Component
public class RealTimeNotify extends Notify {

    public void execute(Long ruleId, String cloudAccountId, Long version) {
        RulePO rulePO = ruleMapper.selectByPrimaryKey(ruleId);
        if (rulePO == null || !Status.valid.name().equals(rulePO.getStatus())) {
            return;
        }
        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(cloudAccountId);
        if (cloudAccountPO == null || !Status.valid.name().equals(cloudAccountPO.getAccountStatus())) {
            return;
        }

        // Build query conditions: new unprocessed risks
        RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder()
                .cloudAccountIdList(List.of(cloudAccountPO.getCloudAccountId()))
                .status(RiskStatusManager.RiskStatus.UNREPAIRED.name())
                .ruleId(rulePO.getId())
                .isNew(1)
                .version(version)
                .build();
        List<RuleScanResultPO> data = ruleScanResultMapper.findList(ruleScanResultDTO);
        if (data == null || data.isEmpty()) {
            return;
        }

        // Query subscription rules
        SubscriptionDTO subscriptionDTO = new SubscriptionDTO();
        subscriptionDTO.setStatus(Status.valid.name());
        List<SubscriptionPO> list = subscriptionMapper.list(subscriptionDTO);
        if (list.isEmpty()) {
            return;
        }

        for (SubscriptionPO subscriptionPO : list) {
            // Query real-time alarm actions
            List<SubscriptionActionPO> subscriptionActionPOList = subscriptionActionMapper
                    .findList(subscriptionPO.getId(), SubscriptionType.realtime.name());
            if (subscriptionActionPOList.isEmpty()) {
                continue;
            }

            // Query risk and filter results
            List<RuleScanResultPO> ruleScanResultPOList = filterList(data, FilterParam.buildParam(rulePO, cloudAccountPO), subscriptionPO.getRuleConfigJson());
            if (ruleScanResultPOList.isEmpty()) {
                log.info("ruleId {} cloudAccountId {} The rule scan result is empty and execution is skipped.", rulePO.getId(),
                        cloudAccountPO.getCloudAccountId());
                continue;
            }

            // alarm
            for (SubscriptionActionPO subscriptionActionPO : subscriptionActionPOList) {
                if (SubscriptionType.Action.interfaceCallback.name().equals(subscriptionActionPO.getAction())) {
                    interfaceCallBack(subscriptionActionPO.getUrl(), ruleScanResultPOList);
                } else {
                    executeNotify(SubscriptionType.getName(subscriptionActionPO.getActionType()),
                            SubscriptionType.Action.getName(subscriptionActionPO.getAction()),
                            subscriptionActionPO.getUrl(), subscriptionPO.getName(), ruleScanResultPOList);
                }
            }
        }
    }
}
