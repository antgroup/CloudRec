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
package com.alipay.application.service.risk;

import com.alipay.common.enums.Action;
import com.alipay.common.enums.LogType;
import com.alipay.common.exception.BizException;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.OperationLogMapper;
import com.alipay.dao.mapper.RuleScanResultMapper;
import com.alipay.dao.po.OperationLogPO;
import com.alipay.dao.po.RuleScanResultPO;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.List;

/*
 *@title RiskStatus
 *@description 风险状态管理
 *@author jietian
 *@version 1.0
 *@create 2024/7/17 09:28
 */
@Slf4j
@Component
public class RiskStatusManager {

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private OperationLogMapper operationLogMapper;

    public enum RiskStatus {
        REPAIRED, // 已修复
        UNREPAIRED, // 未修复
        IGNORED, // 已忽略
        WHITED, // 已加白
    }

    private void saveOperationLog(Long id, Action.RiskAction action, String userId, String notes) {
        OperationLogPO operationLogPO = new OperationLogPO();
        operationLogPO.setAction(action.getName());
        operationLogPO.setUserId(userId);
        operationLogPO.setNotes(notes);
        operationLogPO.setType(LogType.RISK.name());
        operationLogPO.setCorrelationId(id);
        operationLogMapper.insertSelective(operationLogPO);
    }

    /**
     * 已修复 => 未修复
     *
     * @param id 风险ID
     */
    public void repairedToUnrepaired(Long id) {
        RiskStatus riskStatus = getRiskStatus(id);
        if (riskStatus != RiskStatus.REPAIRED) {
            log.info("The current risk state is not a repaired state, id: {}", id);
            return;
        }

        RuleScanResultPO ruleScanResultPO = new RuleScanResultPO();
        ruleScanResultPO.setId(id);
        ruleScanResultPO.setStatus(RiskStatus.UNREPAIRED.name());
        ruleScanResultMapper.updateByPrimaryKeySelective(ruleScanResultPO);

        // 记录日志
        saveOperationLog(id, Action.RiskAction.REPAIRED, "SYSTEM", "风险从已修复状态变更为未修复状态");
    }

    /**
     * 未修复 => 已修复
     *
     * @param id 风险ID
     */
    public void unrepairedToRepaired(Long id) {
        RiskStatus riskStatus = getRiskStatus(id);
        if (riskStatus != RiskStatus.UNREPAIRED) {
            log.info("The current risk state is not an unrepaired state, id: {}", id);
            return;
        }

        RuleScanResultPO ruleScanResultPO = new RuleScanResultPO();
        ruleScanResultPO.setId(id);
        ruleScanResultPO.setStatus(RiskStatus.REPAIRED.name());
        ruleScanResultMapper.updateByPrimaryKeySelective(ruleScanResultPO);

        // 记录日志
        saveOperationLog(id, Action.RiskAction.REPAIRED, "SYSTEM", "风险从未修复状态变更为已修复状态");
    }


    /**
     * 未修复 => 已修复
     *
     */
    public void unrepairedToRepaired(String resourceId, String resourceType, String platform) {
        RuleScanResultDTO resultDTO = RuleScanResultDTO.builder().resourceId(resourceId).resourceType(resourceType).platform(platform).build();
        List<RuleScanResultPO> idList = ruleScanResultMapper.findIdList(resultDTO);
        if (CollectionUtils.isEmpty(idList)) {
            return;
        }

        for (RuleScanResultPO ruleScanResultPO : idList) {
            unrepairedToRepaired(ruleScanResultPO.getId());
        }
    }

    /**
     * 未修复 => 忽略
     *
     * @param id 风险ID
     */
    public void unrepairedToIgnored(Long id, String operator, String ignoreReasonType, String ignoreReason) {
        RiskStatus riskStatus = getRiskStatus(id);
        if (riskStatus != RiskStatus.UNREPAIRED) {
            log.info("The current risk state is not an unrepaired state, id: {}", id);
            return;
        }

        RuleScanResultPO ruleScanResultPO = new RuleScanResultPO();
        ruleScanResultPO.setId(id);
        ruleScanResultPO.setStatus(RiskStatus.IGNORED.name());
        ruleScanResultPO.setIgnoreReasonType(ignoreReasonType);
        ruleScanResultPO.setIgnoreReason(ignoreReason);
        ruleScanResultMapper.updateByPrimaryKeySelective(ruleScanResultPO);

        saveOperationLog(id, Action.RiskAction.IGNORE_RISK, operator,
                "忽略原因类型:" + ignoreReasonType + "\n" + "忽略原因:" + ignoreReason);
    }

    /**
     * 忽略 => 未修复
     *
     * @param id 风险ID
     */
    public void ignoredToUnrepaired(Long id, String operator) {
        RiskStatus riskStatus = getRiskStatus(id);
        if (riskStatus != RiskStatus.IGNORED) {
            log.info("The current risk state is not an ignored state, id: {}", id);
            return;
        }

        RuleScanResultPO ruleScanResultPO = new RuleScanResultPO();
        ruleScanResultPO.setId(id);
        ruleScanResultPO.setStatus(RiskStatus.UNREPAIRED.name());
        ruleScanResultPO.setIgnoreReason("");
        ruleScanResultPO.setIgnoreReasonType("");
        ruleScanResultMapper.updateByPrimaryKeySelective(ruleScanResultPO);

        saveOperationLog(id, Action.RiskAction.CANCEL_IGNORE_RISK, operator, "取消风险忽略状态");
    }

    /**
     * 检测用户输入的status是否包含在RiskStatus 范围内
     */
    public static boolean isValidStatus(String status) {
        for (RiskStatus s : RiskStatus.values()) {
            if (s.name().equals(status)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取风险当前状态
     *
     * @param id 规则扫描结果id
     * @return 当前风险状态
     */
    public RiskStatus getRiskStatus(Long id) {
        RuleScanResultPO ruleScanResultPO = ruleScanResultMapper.selectByPrimaryKey(id);
        if (ruleScanResultPO == null) {
            log.info("The current risk state is not a valid id, id: {}", id);
            return null;
        }

        return RiskStatus.valueOf(ruleScanResultPO.getStatus());
    }

    public static Boolean isCanWhitedStatus(String status) {
        if (status.equals(RiskStatus.WHITED.name()) || status.equals(RiskStatus.UNREPAIRED.name())) {
            return true;
        }
        return false;
    }
}
