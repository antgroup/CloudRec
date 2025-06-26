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

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.common.RealTimeNotify;
import com.alipay.application.service.common.utils.DBDistributedLockUtil;
import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.common.utils.SpringUtils;
import com.alipay.application.service.resource.IQueryResource;
import com.alipay.application.service.resource.task.ResourceMergerTask;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.application.service.rule.RuleServiceImpl;
import com.alipay.application.service.rule.WhitedRegoMatcher;
import com.alipay.application.service.rule.WhitedRuleEngineMatcher;
import com.alipay.application.service.rule.domain.RuleAgg;
import com.alipay.application.service.rule.domain.RuleGroup;
import com.alipay.application.service.rule.domain.repo.OpaRepository;
import com.alipay.application.service.rule.domain.repo.RuleGroupRepository;
import com.alipay.application.service.rule.domain.repo.RuleRepository;
import com.alipay.application.service.rule.enums.Field;
import com.alipay.application.service.statistics.job.StatisticsJob;
import com.alipay.application.share.request.rule.LinkDataParam;
import com.alipay.application.share.request.rule.WhitedRuleConfigDTO;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.common.constant.OpaFlagConstants;
import com.alipay.common.constant.RuleGroupConstants;
import com.alipay.common.enums.*;
import com.alipay.common.exception.BizException;
import com.alipay.common.utils.DateUtil;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import jakarta.validation.constraints.NotNull;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.concurrent.*;

/*
 *@title ScanServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/6/18 09:12
 */
@Service
public class ScanServiceImpl implements ScanService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScanServiceImpl.class);

    @Resource
    private RuleGroupMapper ruleGroupMapper;

    @Resource
    private OpaRepository opaRepository;

    @Resource
    private RuleRepository ruleRepository;

    @Resource
    private RuleGroupRepository ruleGroupRepository;

    @Resource
    private IQueryResource iQueryResource;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private CloudAccountMapper cloudAccountMapper;

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    @Resource
    private RealTimeNotify realTimeNotify;

    @Resource
    private RuleScanContext ruleScanContext;

    @Resource
    private RiskStatusManager riskStatusManager;

    @Resource
    private DbCacheUtil dbCacheUtil;

    @Resource
    private WhitedRuleEngineMatcher whitedRuleEngineMatcher;

    @Resource
    private WhitedRegoMatcher whitedRegoMatcher;

    @Resource
    private OperationLogMapper operationLogMapper;

    @Resource
    private StatisticsJob statisticsJob;

    @Resource
    private DBDistributedLockUtil dbDistributedLockUtil;

    @Resource
    private WhitedConfigContext whitedConfigContext;

    /**
     * localLockPrefix
     */
    private static final String localLockPrefix = "rule::scan::running::";

    @Override
    public void scanByGroup(Long groupId) {
        RuleGroup ruleGroup = ruleGroupRepository.findOne(groupId);
        if (ruleGroup == null) {
            LOGGER.warn("No rule group for groupId:{}", groupId);
            return;
        }

        List<RuleAgg> list = ruleRepository.findByGroupId(groupId, Status.valid.name());
        if (CollectionUtils.isEmpty(list)) {
            LOGGER.warn("No rule for groupId:{}", groupId);
            return;
        }

        Date startTime = new Date();
        list.forEach(ruleAgg -> scanByRule(ruleAgg.getId()));
        ruleGroup.setLastScanStartTime(startTime);
        ruleGroup.setLastScanEndTime(new Date());
        ruleGroupRepository.save(ruleGroup);
    }

    @Override
    public void scanAll() {
        RuleGroupPO ruleGroupPO = ruleGroupMapper.findOne(RuleGroupConstants.DEFAULT_GROUP);
        if (ruleGroupPO == null) {
            throw new BizException("The default rule group does not exist");
        }

        scanByGroup(ruleGroupPO.getId());
    }

    /**
     * 任务分片，递归抢占其他执行器未执行的任务
     * <p>
     * 24h内同一个规则只会执行一次扫描任务
     */
    @Override
    public void shardingScanAll() {

    }

    private static final int MAX_BATCH_SIZE = 1000;

    private static final ExecutorService executorService = new ThreadPoolExecutor(
            8,
            8,
            1L,
            TimeUnit.MINUTES,
            new LinkedBlockingQueue<>(1000),
            Executors.defaultThreadFactory(),
            new ThreadPoolExecutor.CallerRunsPolicy());

    private long getNextVersion(Long ruleId, String cloudAccountId) {
        Long version = ruleScanResultMapper.findMaxVersion(ruleId, cloudAccountId);
        return version == null ? 1 : version + 1;
    }

    public void scanByRule(RuleAgg ruleAgg, @NotNull CloudAccountPO cloudAccountPO) {
        String cloudAccountId = cloudAccountPO.getCloudAccountId();
        LOGGER.info("Scan by rule name:{} cloudAccountId:{}", ruleAgg.getRuleName(), cloudAccountId);
        long nextVersion = getNextVersion(ruleAgg.getId(), cloudAccountId);

        List<CloudResourceInstancePO> resourceInstances = iQueryResource.queryByCond(ruleAgg.getPlatform(),
                ruleAgg.getResourceType(), cloudAccountId, 0L, 1);
        if (CollectionUtils.isEmpty(resourceInstances)) {
            handleAccountScanResultFinish(ruleAgg, cloudAccountId, nextVersion);
            return;
        }

        // Determine whether there is a risk mark on the account and reduce unnecessary
        // SQL queries
        boolean accountExistRiskFlag = false;

        long scrollId = 0L;
        while (true) {
            resourceInstances = iQueryResource.queryByCond(ruleAgg.getPlatform(), ruleAgg.getResourceType(),
                    cloudAccountId, scrollId, MAX_BATCH_SIZE);
            resourceInstances = ResourceMergerTask.mergeJson(LinkDataParam.deserializeList(ruleAgg.getLinkedDataList()),
                    resourceInstances, cloudAccountId);
            for (CloudResourceInstancePO resourceInstance : resourceInstances) {
                Map<String, Object> result = opaRepository.callOpa(ruleAgg.getRegoPath(), ruleAgg.getRegoPolicy(),
                        resourceInstance.getInstance());
                if (result == null) {
                    LOGGER.warn("Execute rule failed");
                    continue;
                }

                // Analyze the execution results if there are risks
                Object o = result.get(OpaFlagConstants.RISK_MARKING);
                if (o == null) {
                    continue;
                }

                if (o instanceof Boolean && (Boolean) o) {
                    accountExistRiskFlag = true;
                    result.put(Field.ResourceId.getFieldName(), resourceInstance.getResourceId());
                    result.put(Field.ResourceName.getFieldName(), resourceInstance.getResourceName());
                    if (StringUtils.isNotBlank(resourceInstance.getAddress())) {
                        result.put(Field.PublicIp.getFieldName(), resourceInstance.getAddress());
                    }
                    if (StringUtils.isNotBlank(resourceInstance.getRegion())) {
                        result.put(Field.Region.getFieldName(), resourceInstance.getRegion());
                    }

                    saveOrUpdate(resourceInstance, result, nextVersion, ruleAgg, cloudAccountPO);
                }
            }

            if (resourceInstances.size() < MAX_BATCH_SIZE) {
                break;
            }

            scrollId = resourceInstances.get(resourceInstances.size() - 1).getId();

            // help gc
            resourceInstances.clear();
        }

        boolean needNotify = accountExistRiskFlag;
        executorService.execute(() -> {
            if (needNotify) {
                // Execute subscription alarm: risk real-time alarm
                realTimeNotify.execute(ruleAgg.getId(), cloudAccountId, nextVersion);
            }
            // Update risk status: Modify the risk status of the previous version to
            // resolved
            handleAccountScanResultFinish(ruleAgg, cloudAccountId, nextVersion);
        });

        try {
            Thread.sleep(200);
            // System.gc();
        } catch (InterruptedException e) {
            LOGGER.error("Thread sleep error", e);
        }
    }

    /**
     * 云账号指定资产类型的全部未处理的风险修改为已处理
     *
     * @param ruleAgg
     * @param cloudAccountId
     * @param nextVersion
     */
    protected void handleAccountScanResultFinish(RuleAgg ruleAgg, String cloudAccountId, Long nextVersion) {
        // The first version shows that there is no data before and no state change is
        // required
        if (nextVersion == 1) {
            return;
        }

        List<RuleScanResultPO> ruleScanResultPOList = ruleScanResultMapper.find(ruleAgg.getId(), cloudAccountId,
                List.of(RiskStatusManager.RiskStatus.UNREPAIRED.name()), nextVersion);
        LOGGER.info("cloudAccountId:{},ruleName:{},handleAccountScanResultFinish: ruleScanResultPOList size: {}",
                cloudAccountId, ruleAgg.getRuleName(), ruleScanResultPOList.size());
        for (RuleScanResultPO ruleScanResultPO : ruleScanResultPOList) {
            riskStatusManager.unrepairedToRepaired(ruleScanResultPO.getId());
        }
    }

    /**
     * 云账号指定资产类型的全部未处理的风险修改为已处理
     *
     * @param ruleAgg
     * @param cloudAccountId
     */
    protected void handleAccountScanResultFinish(RuleAgg ruleAgg, String cloudAccountId) {
        RuleScanResultDTO resultDTO = RuleScanResultDTO.builder()
                .cloudAccountIdList(Collections.singletonList(cloudAccountId)).ruleId(ruleAgg.getId())
                .statusList(List.of(RiskStatusManager.RiskStatus.UNREPAIRED.name())).build();
        List<RuleScanResultPO> ruleScanResultPOList = ruleScanResultMapper.findList(resultDTO);
        LOGGER.info("cloudAccountId:{},ruleName:{},handleAccountScanResultFinish: ruleScanResultPOList size: {}",
                cloudAccountId, ruleAgg.getRuleName(), ruleScanResultPOList.size());
        for (RuleScanResultPO ruleScanResultPO : ruleScanResultPOList) {
            riskStatusManager.unrepairedToRepaired(ruleScanResultPO.getId());
        }
    }

    private void handleScanResultFinish(RuleAgg ruleAgg) {
        ruleAgg.setRunningEndStatus();
        ruleRepository.save(ruleAgg);
        statisticsJob.ruleScanResultCountStatistics(ruleAgg.getId());
    }

    /**
     * Detect all rules
     *
     * @param ruleId ruleId
     * @return ApiResponse
     */
    public ApiResponse<String> scanByRule(@NotNull Long ruleId) {
        RuleAgg ruleAgg = ruleRepository.findByRuleId(ruleId);
        if (ruleAgg == null) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "The current rule does not exist");
        }

        // 1 h 分布式锁，防止段时间多次点击
        if (!dbDistributedLockUtil.tryLock(localLockPrefix + ruleId, 1000 * 60 * 60)) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "The current rule is running");
        }

        // 业务逻辑判断，防止1小时未运行完成的规则，再次运行
        if (ruleAgg.getIsRunning() == 1) {
            return new ApiResponse<>(ApiResponse.FAIL_CODE, "The current rule is running");
        }

        // 修改状态
        ruleAgg.setRunningStartStatus();
        ruleRepository.save(ruleAgg);

        try {
            // Loading rules to opa
            ruleScanContext.loadByRuleId(ruleId);
            // Loading whitedConfigs to opa
            whitedConfigContext.loadEnableWhitedConfigs();

            // Query the account account with this asset to optimize the speed
            List<String> cloudAccountIdList = cloudResourceInstanceMapper.findAccountList(ruleAgg.getPlatform(),
                    ruleAgg.getResourceType());

            CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder()
                    .platformList(List.of(ruleAgg.getPlatform()))
                    .accountStatus(Status.valid.name())
                    .build();

            List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);

            // 获取所有的白名单规则
            whitedConfigContext.initWhitedConfigCache();
            for (CloudAccountPO cloudAccountPO : cloudAccountPOS) {
                if (!cloudAccountIdList.contains(cloudAccountPO.getCloudAccountId())) {
                    // 20250416 bugfix：云账号对应的资产已经不存在，将风险状态更新为已解决
                    handleAccountScanResultFinish(ruleAgg, cloudAccountPO.getCloudAccountId());
                    continue;
                }

                try {
                    scanByRule(ruleAgg, cloudAccountPO);
                } catch (Exception e) {
                    LOGGER.error("cloudAccountId:{} run rule:{} fail:{}", cloudAccountPO.getCloudAccountId(),
                            ruleAgg.getRuleCode(), e.getMessage());
                }
            }
        } catch (Exception e) {
            LOGGER.error("run rule:{} fail:{}", ruleAgg.getRuleCode(), e.getMessage());
        } finally {
            // 改状态、释放锁
            handleScanResultFinish(ruleAgg);
            // 确保线程池复用线程时清理旧数据
            if (Thread.currentThread().isAlive()) {
                whitedConfigContext.clear();
            }
            dbDistributedLockUtil.releaseLock(localLockPrefix + ruleId);
        }

        dbCacheUtil.clear(RuleServiceImpl.cacheKey);

        return ApiResponse.SUCCESS;
    }

    protected void saveOrUpdate(CloudResourceInstancePO resourceInstance, Map<String, Object> result,
            Long version, RuleAgg ruleAgg, CloudAccountPO cloudAccountPO) {
        RuleScanResultPO ruleScanResultPO = ruleScanResultMapper.fineOne(resourceInstance.getResourceId(),
                resourceInstance.getCloudAccountId(), ruleAgg.getId());

        if (ruleScanResultPO == null) {
            ruleScanResultPO = new RuleScanResultPO();
            finishData(ruleScanResultPO, resourceInstance, ruleAgg.getId(), ruleAgg.getRegoPolicy(),
                    cloudAccountPO.getTenantId(), result, version);
            ruleScanResultPO.setIsNew(1);
            ruleScanResultMapper.insertSelective(ruleScanResultPO);
            // 获取风险id && 更新加白状态
            scanWhitedRuleConfig(ruleScanResultPO, ruleAgg.getRuleCode(), cloudAccountPO, resourceInstance);
            ruleScanResultMapper.updateByPrimaryKeySelective(ruleScanResultPO);
        } else {
            finishData(ruleScanResultPO, resourceInstance, ruleAgg.getId(), ruleAgg.getRegoPolicy(),
                    cloudAccountPO.getTenantId(), result, version);
            ruleScanResultPO.setIsNew(0);
            scanWhitedRuleConfig(ruleScanResultPO, ruleAgg.getRuleCode(), cloudAccountPO, resourceInstance);
            ruleScanResultMapper.updateByPrimaryKeySelective(ruleScanResultPO);
        }
    }

    private void scanWhitedRuleConfig(RuleScanResultPO ruleScanResultPO, String ruleCode, CloudAccountPO cloudAccountPO,
            CloudResourceInstancePO resourceInstance) {
        List<WhitedRuleConfigPO> whitedRuleConfigPOList = whitedConfigContext.get();
        String hitWhitedRuleName = null;
        Long hitWhitedRuleConfigId = null;
        boolean isWhited = false;
        for (WhitedRuleConfigPO whitedRuleConfigPO : whitedRuleConfigPOList) {
            if (!StringUtils.isEmpty(whitedRuleConfigPO.getRiskRuleCode())) {
                if (StringUtils.isEmpty(ruleCode) || !ruleCode.equals(whitedRuleConfigPO.getRiskRuleCode())) {
                    continue;
                }
            }

            if (whitedRuleConfigPO.getRuleType().equals(WhitedRuleTypeEnum.RULE_ENGINE.name())) {
                List<WhitedRuleConfigDTO> whitedRuleConfigDTOS = JSON.parseArray(whitedRuleConfigPO.getRuleConfig(),
                        WhitedRuleConfigDTO.class);
                isWhited = whitedRuleEngineMatcher.matchWhitelistRule(whitedRuleConfigDTOS,
                        whitedRuleConfigPO.getCondition(), ruleScanResultPO);
            } else if (whitedRuleConfigPO.getRuleType().equals(WhitedRuleTypeEnum.REGO.name())) {
                isWhited = whitedRegoMatcher.executeRegoMatch(whitedRuleConfigPO.getRegoContent(),
                        whitedRuleConfigPO.getId().toString(), ruleScanResultPO, cloudAccountPO, resourceInstance);
            }
            if (isWhited) {
                hitWhitedRuleName = whitedRuleConfigPO.getRuleName();
                hitWhitedRuleConfigId = whitedRuleConfigPO.getId();
                break;
            }
        }
        LOGGER.info("Update ruleScanResult status:{},hitWhitedRuleName:{},ruleScanResult_id:{}", isWhited,
                hitWhitedRuleName, ruleScanResultPO.getId());
        if (isWhited) {
            ruleScanResultPO.setWhitedId(hitWhitedRuleConfigId);
        }
        if (isWhited && ruleScanResultPO.getStatus().equals(RiskStatusManager.RiskStatus.UNREPAIRED.name())) {
            ruleScanResultPO.setGmtModified(new Date());
            ruleScanResultPO.setStatus(RiskStatusManager.RiskStatus.WHITED.name());
            saveOperationLog(ruleScanResultPO.getId(), Action.RiskAction.WHITED, "system",
                    String.format("命中白名单规则:%s, 风险从未修复状态变更为已加白状态", hitWhitedRuleName));
        } else if (!isWhited && ruleScanResultPO.getStatus().equals(RiskStatusManager.RiskStatus.WHITED.name())) {
            ruleScanResultPO.setStatus(RiskStatusManager.RiskStatus.UNREPAIRED.name());
            ruleScanResultPO.setGmtModified(new Date());
            ruleScanResultPO.setWhitedId(null);
            saveOperationLog(ruleScanResultPO.getId(), Action.RiskAction.CANCEL_WHITED, "system",
                    "未命中白名单规则, 风险从已加白状态变更为未修复状态");
        }
    }

    private void saveOperationLog(Long id, Action.RiskAction action, String userId, String notes) {
        OperationLogPO operationLogPO = new OperationLogPO();
        operationLogPO.setAction(action.getName());
        operationLogPO.setUserId(userId);
        operationLogPO.setNotes(notes);
        operationLogPO.setType(LogType.RISK.name());
        operationLogPO.setCorrelationId(id);
        operationLogMapper.insertSelective(operationLogPO);
        if (Objects.isNull(id)) {
            LOGGER.info("saveOperationLog not CorrelationId， OperationLogPO id:{}", operationLogPO.getId());
        }
    }

    /**
     * @param ruleScanResultPO 风险扫描对象
     * @param resourceInstance 资源实例
     * @param ruleId           规则id
     * @param regoPolicy       规则策略
     * @param tenantId         租户id
     * @param result           rego扫描结果
     * @param version          数据版本
     */
    private void finishData(RuleScanResultPO ruleScanResultPO,
            CloudResourceInstancePO resourceInstance,
            Long ruleId,
            String regoPolicy,
            Long tenantId,
            Map<String, Object> result,
            Long version) {

        ruleScanResultPO.setRuleSnapshoot(regoPolicy);
        ruleScanResultPO.setResourceStatus(ResourceStatus.exist.name());
        ruleScanResultPO.setTenantId(tenantId);
        ruleScanResultPO.setResourceSnapshoot(resourceInstance.getInstance());
        ruleScanResultPO.setUpdateTime(DateUtil.dateToString(resourceInstance.getGmtModified()));
        ruleScanResultPO.setVersion(version);
        ruleScanResultPO.setRuleId(ruleId);
        ruleScanResultPO.setCloudAccountId(resourceInstance.getCloudAccountId());
        ruleScanResultPO.setTenantId(resourceInstance.getTenantId());
        ruleScanResultPO.setPlatform(resourceInstance.getPlatform());
        ruleScanResultPO.setResourceType(resourceInstance.getResourceType());
        ruleScanResultPO.setResourceId(resourceInstance.getResourceId());
        ruleScanResultPO.setResourceName(resourceInstance.getResourceName());
        ruleScanResultPO.setResult(JSON.toJSONString(result));
        ruleScanResultPO.setCloudResourceInstanceId(resourceInstance.getId());

        // Resolved status changes to unresolved
        if (RiskStatusManager.RiskStatus.REPAIRED.name().equals(ruleScanResultPO.getStatus())) {
            RiskStatusManager riskStatusManager = SpringUtils.getApplicationContext().getBean(RiskStatusManager.class);
            riskStatusManager.repairedToUnrepaired(ruleScanResultPO.getId());
        }

        // Change the risk state
        // The state has been ignored and does not change the state
        if (!RiskStatusManager.RiskStatus.IGNORED.name().equals(ruleScanResultPO.getStatus())
                && !RiskStatusManager.RiskStatus.WHITED.name().equals(ruleScanResultPO.getStatus())) {
            ruleScanResultPO.setStatus(RiskStatusManager.RiskStatus.UNREPAIRED.name());
        }

        if (RiskStatusManager.RiskStatus.UNREPAIRED.name().equals(ruleScanResultPO.getStatus())) {
            ruleScanResultPO.setGmtModified(new Date());
        }
    }
}
