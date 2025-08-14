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
import com.alipay.common.utils.DateUtil;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.dto.SubscriptionDTO;
import com.alipay.dao.po.*;
import com.alipay.application.service.common.enums.SubscriptionType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/*
 *@title 定时通知
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/9/18 13:58
 */
@Slf4j
@Component
public class TimingNotify extends Notify {

    public void execute() {
        // Load the account account
        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(CloudAccountDTO.builder().accountStatus(Status.valid.name()).build());

        List<RulePO> rulePOS = ruleMapper.findList(RuleDTO.builder().status(Status.valid.name()).build());
        for (RulePO rulePO : rulePOS) {
            for (CloudAccountPO cloudAccountPO : cloudAccountPOS) {
                // 1. Load risk data
                RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder().ruleId(rulePO.getId()).cloudAccountIdList(List.of(cloudAccountPO.getCloudAccountId())).status(RiskStatusManager.RiskStatus.UNREPAIRED.name()).build();

                List<RuleScanResultPO> data = ruleScanResultMapper.findList(ruleScanResultDTO);

                // 2. Perform rule filtering
                SubscriptionDTO subscriptionDTO = new SubscriptionDTO();
                subscriptionDTO.setStatus(Status.valid.name());
                List<SubscriptionPO> list = subscriptionMapper.list(subscriptionDTO);
                if (list.isEmpty()) {
                    return;
                }

                for (SubscriptionPO subscriptionPO : list) {
                    // Query real-time alarm actions
                    List<SubscriptionActionPO> subscriptionActionPOList = subscriptionActionMapper.findList(subscriptionPO.getId(), SubscriptionType.timing.name());
                    if (subscriptionActionPOList.isEmpty()) {
                        continue;
                    }

                    List<RuleScanResultPO> ruleScanResultPOList = filterList(data, FilterParam.buildParam(rulePO, cloudAccountPO), subscriptionPO.getRuleConfigJson());
                    if (ruleScanResultPOList.isEmpty()) {
                        log.info("ruleId {} cloudAccountId {} The rule scan result is empty and execution is skipped.", rulePO.getId(), cloudAccountPO.getCloudAccountId());
                        continue;
                    }

                    for (SubscriptionActionPO subscriptionActionPO : subscriptionActionPOList) {
                        // Determine whether an alarm is required
                        boolean doAction = judgeNotifyCond(subscriptionActionPO);
                        if (!doAction) {
                            log.info("Subscription id: {}, rule id: {}, alarm conditions not met", subscriptionPO.getId(), subscriptionActionPO.getSubscriptionId());
                            continue;
                        }

                        executeNotify(SubscriptionType.getName(subscriptionActionPO.getActionType()), SubscriptionType.Action.getName(subscriptionActionPO.getAction()), subscriptionActionPO.getUrl(), subscriptionPO.getName(), ruleScanResultPOList);
                    }
                }
            }
        }
    }


    /**
     * Determine whether the alarm is triggered
     */
    private static boolean judgeNotifyCond(SubscriptionActionPO subscriptionActionPO) {
        boolean notify = false;
        // Determine whether the alarm conditions are met
        String period = subscriptionActionPO.getPeriod();
        if (!"all".equals(period)) {
            if (DateUtil.getDayNumber().equals(period)) {
                String[] timeList = subscriptionActionPO.getTimeList().split(",");
                for (String hour : timeList) {
                    if (DateUtil.getCurrentHour() == Integer.parseInt(hour)) {
                        notify = true;
                        break;
                    }
                }
            }
        } else {
            // Determine the alarm time
            String[] timeList = subscriptionActionPO.getTimeList().split(",");
            for (String hour : timeList) {
                if (DateUtil.getCurrentHour() == Integer.parseInt(hour)) {
                    notify = true;
                    break;
                }
            }
        }

        return notify;
    }
}
