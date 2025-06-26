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

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.application.service.system.domain.Tenant;
import com.alipay.application.service.system.domain.repo.TenantRepository;
import com.alipay.common.constant.TenantConstants;
import com.alipay.common.enums.Status;
import com.alipay.common.exception.BizException;
import com.alipay.common.utils.DateUtil;
import com.alipay.dao.dto.*;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/*
 *@title StatisticsJobImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/10/11 17:27
 */
@Slf4j
@Service
public class StatisticsJobImpl implements StatisticsJob {

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private CloudAccountMapper cloudAccountMapper;

    @Resource
    private DailyRiskManagementMapper dailyRiskManagementMapper;

    @Resource
    private TenantMapper tenantMapper;

    @Resource
    private HistoryDataEverydayStatisticsMapper historyDataEverydayStatisticsMapper;

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    @Resource
    private ResourceMapper resourceMapper;

    @Resource
    private CloudResourceRiskCountStatisticsMapper cloudResourceRiskCountStatisticsMapper;

    @Resource
    private RuleScanRiskCountStatisticsMapper ruleScanRiskCountStatisticsMapper;

    @Resource
    private TenantRepository tenantRepository;


    @Override
    public void dailyRiskManagementStatistics() {
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().build();
        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
        Map<Long, List<CloudAccountPO>> collect = cloudAccountPOS.stream()
                .collect(Collectors.groupingBy(CloudAccountPO::getTenantId));

        String date = DateUtil.dateToString(new Date());
        for (Long tenantId : collect.keySet()) {
            List<CloudAccountPO> cloudAccountPOList = collect.get(tenantId);
            List<String> cloudAccoutIdList = cloudAccountPOList.stream().map(CloudAccountPO::getCloudAccountId)
                    .toList();

            int handleCount = ruleScanResultMapper
                    .findCount(RuleScanResultDTO.builder().cloudAccountIdList(cloudAccoutIdList)
                            .statusList(Arrays.asList(RiskStatusManager.RiskStatus.REPAIRED.name(),
                                    RiskStatusManager.RiskStatus.IGNORED.name()))
                            .build());
            int notHandleCount = ruleScanResultMapper
                    .findCount(RuleScanResultDTO.builder().cloudAccountIdList(cloudAccoutIdList)
                            .status(RiskStatusManager.RiskStatus.UNREPAIRED.name()).build());

            saveDailyRiskManagementData(date, tenantId, handleCount, notHandleCount);
        }

        TenantPO tenantPO = tenantMapper.findByTenantName(TenantConstants.GLOBAL_TENANT);
        if (tenantPO == null) {
            return;
        }

        // 查询全局租户数据
        int handleCount = ruleScanResultMapper.findCount(
                RuleScanResultDTO.builder().statusList(Arrays.asList(RiskStatusManager.RiskStatus.REPAIRED.name(),
                        RiskStatusManager.RiskStatus.IGNORED.name())).build());
        int notHandleCount = ruleScanResultMapper
                .findCount(RuleScanResultDTO.builder().status(RiskStatusManager.RiskStatus.UNREPAIRED.name()).build());

        saveDailyRiskManagementData(date, tenantPO.getId(), handleCount, notHandleCount);
    }

    private void saveDailyRiskManagementData(String date, Long tenantId, int handleCount, int notHandleCount) {
        DailyRiskManagementPO dailyRiskManagementPO = dailyRiskManagementMapper.findOne(date, tenantId);
        if (dailyRiskManagementPO == null) {
            dailyRiskManagementPO = new DailyRiskManagementPO();
            dailyRiskManagementPO.setTenantId(tenantId);
            dailyRiskManagementPO.setCreateDate(date);
            dailyRiskManagementPO.setHandleCount(handleCount);
            dailyRiskManagementPO.setNotHandleCount(notHandleCount);
            dailyRiskManagementMapper.insertSelective(dailyRiskManagementPO);
        } else {
            dailyRiskManagementPO.setNotHandleCount(notHandleCount);
            dailyRiskManagementPO.setHandleCount(handleCount);
            dailyRiskManagementPO.setGmtModified(new Date());
            dailyRiskManagementMapper.updateByPrimaryKeySelective(dailyRiskManagementPO);
        }
    }

    @Override
    public void historyDataEverydayStatistics() {
        // init some data
        Date yesterdayEndTime = DateUtil.getYesterdayEndTime();

        // clear history data
        ruleScanRiskCountStatisticsMapper.deleteByDate(yesterdayEndTime);

        List<TenantPO> tenantPOS = tenantMapper.findList(new TenantDTO());
        for (TenantPO tenantPO : tenantPOS) {
            queryData(tenantPO.getTenantName(), tenantPO.getId(), yesterdayEndTime);
        }
    }

    private void queryData(String tenantName, Long tenantId, Date yesterdayEndTime) {
        Long tempTenantId = tenantId;
        if (TenantConstants.GLOBAL_TENANT.equals(tenantName)) {
            tenantId = null;
        }

        HistoryDataEverydayStatisticsPO historyDataEverydayStatisticsPO = new HistoryDataEverydayStatisticsPO();
        // 1. Get account account
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder()
                .tenantId(tenantId)
                .gmtCreateEnd(yesterdayEndTime)
                .build();

        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
        if (!CollectionUtils.isEmpty(cloudAccountPOS)) {
            // 2. Get the number of account platforms
            long platformCount = cloudAccountPOS.stream().map(CloudAccountPO::getPlatform).distinct().count();

            // 3. get resource quantity
            long cloudResourceInstanceCount = cloudResourceRiskCountStatisticsMapper.findSumResourceCount(tempTenantId);

            // 4. get  risk quantity
            long count = ruleScanRiskCountStatisticsMapper.findSumCount(tempTenantId);

            // Set the data to the historyDataEverydayStatisticsPO
            historyDataEverydayStatisticsPO.setPlatformCount((int) platformCount);
            historyDataEverydayStatisticsPO.setCloudAccountCount(cloudAccountPOS.size());
            historyDataEverydayStatisticsPO.setResourceCount(cloudResourceInstanceCount);
            historyDataEverydayStatisticsPO.setRiskCount(count);
        } else {
            historyDataEverydayStatisticsPO.setPlatformCount(0);
            historyDataEverydayStatisticsPO.setCloudAccountCount(0);
            historyDataEverydayStatisticsPO.setResourceCount(0L);
            historyDataEverydayStatisticsPO.setRiskCount(0L);
        }

        String date = DateUtil.dateToString(yesterdayEndTime);
        historyDataEverydayStatisticsPO.setCreateDate(date);
        historyDataEverydayStatisticsPO.setDetailJson(JSON.toJSONString(historyDataEverydayStatisticsPO));
        historyDataEverydayStatisticsPO.setTenantId(tempTenantId);

        HistoryDataEverydayStatisticsPO existPO = historyDataEverydayStatisticsMapper.findOne(tempTenantId, date);
        if (existPO == null) {
            historyDataEverydayStatisticsMapper.insertSelective(historyDataEverydayStatisticsPO);
        } else {
            historyDataEverydayStatisticsPO.setId(existPO.getId());
            historyDataEverydayStatisticsPO.setGmtModified(new Date());
            historyDataEverydayStatisticsMapper.updateByPrimaryKeySelective(historyDataEverydayStatisticsPO);
        }
    }

    @Override
    public void resourceRiskCountStatistics() {
        List<TenantPO> tenantPOS = tenantMapper.findList(new TenantDTO());
        List<ResourcePO> resourcePOS = resourceMapper.findAll();
        if (CollectionUtils.isEmpty(resourcePOS)) {
            return;
        }

        for (TenantPO tenantPO : tenantPOS) {
            cloudResourceRiskCountStatisticsMapper.deleteByTenantId(tenantPO.getId());
            Long tenantId = tenantPO.getId();
            if (tenantPO.getTenantName().equals(TenantConstants.GLOBAL_TENANT)) {
                tenantId = null;
            }

            for (ResourcePO resourcePO : resourcePOS) {
                // Check the risk count
                RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder()
                        .platform(resourcePO.getPlatform())
                        .tenantId(tenantId)
                        .resourceType(resourcePO.getResourceType())
                        .build();
                RiskCountDTO riskCountDTO = ruleScanResultMapper.findRiskCount(ruleScanResultDTO);

                // Check the number of assets
                IQueryResourceDTO request = IQueryResourceDTO.builder()
                        .platform(resourcePO.getPlatform())
                        .resourceType(resourcePO.getResourceType())
                        .tenantId(tenantId)
                        .build();
                long resourceCount = cloudResourceInstanceMapper.findCountByCond(request);

                CloudResourceRiskCountStatisticsPO cloudResourceRiskCountStatisticsPO = new CloudResourceRiskCountStatisticsPO();
                cloudResourceRiskCountStatisticsPO.setHighLevelRiskCount(riskCountDTO.getHighLevelRiskCount());
                cloudResourceRiskCountStatisticsPO.setMediumLevelRiskCount(riskCountDTO.getMediumLevelRiskCount());
                cloudResourceRiskCountStatisticsPO.setLowLevelRiskCount(riskCountDTO.getLowLevelRiskCount());
                cloudResourceRiskCountStatisticsPO.setTotalRiskCount(riskCountDTO.getTotalRiskCount());
                cloudResourceRiskCountStatisticsPO.setPlatform(resourcePO.getPlatform());
                cloudResourceRiskCountStatisticsPO.setResourceType(resourcePO.getResourceType());
                cloudResourceRiskCountStatisticsPO.setUpdateTime(new Date());
                cloudResourceRiskCountStatisticsPO.setTenantId(tenantPO.getId());
                cloudResourceRiskCountStatisticsPO.setResourceCount((int) resourceCount);

                cloudResourceRiskCountStatisticsMapper.insertSelective(cloudResourceRiskCountStatisticsPO);
            }
        }
    }

    /**
     * Rule scan results statistics
     */
    @Override
    public void ruleScanResultCountStatistics(Long ruleId) {
        try {
            List<Tenant> tenantList = tenantRepository.findAll(Status.valid.name());
            for (Tenant tenant : tenantList) {
                RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder()
                        .ruleId(ruleId)
                        .tenantId(tenant.getId())
                        .status(RiskStatusManager.RiskStatus.UNREPAIRED.name())
                        .build();

                if (tenant.isGlobalTenant()) {
                    ruleScanResultDTO.setTenantId(null);
                }

                int count = ruleScanResultMapper.findCount(ruleScanResultDTO);
                RuleScanRiskCountStatisticsPO ruleScanRiskCountStatisticsPO = new RuleScanRiskCountStatisticsPO();
                ruleScanRiskCountStatisticsPO.setRuleId(ruleId);
                ruleScanRiskCountStatisticsPO.setTenantId(tenant.getId());
                ruleScanRiskCountStatisticsPO.setCount(count);
                ruleScanRiskCountStatisticsPO.setUpdateTime(new Date());

                int i = ruleScanRiskCountStatisticsMapper.deleteByRuleIdAndTenantId(ruleId, tenant.getId());
                log.info("Delete rule scan results statistics records, ruleId:{}, tenantId:{}, count:{}", ruleId, tenant.getId(), i);
                ruleScanRiskCountStatisticsMapper.insertSelective(ruleScanRiskCountStatisticsPO);
            }
        } catch (Exception e) {
            log.error("ruleScanResultCountStatistics error", e);
        }
    }

    /**
     * Statistics all
     */
    @Override
    public void statisticsAll() {
        // 每日风险已处理、未处理统计
        try {
            dailyRiskManagementStatistics();
            // 按租户、资产类型统计风险数量、资产数量

            resourceRiskCountStatistics();

            // 统计历史数据每天的风险数量、资产数量
            historyDataEverydayStatistics();

        } catch (Exception e) {
            log.error("dailyRiskManagementStatistics error", e);
            throw new BizException("statisticsAll error", e);
        }
    }
}
