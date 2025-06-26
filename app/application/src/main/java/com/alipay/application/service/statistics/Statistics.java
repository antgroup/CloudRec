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
package com.alipay.application.service.statistics;

import com.alibaba.fastjson.JSON;
import com.alipay.application.service.common.Platform;
import com.alipay.application.service.common.utils.CacheUtil;
import com.alipay.application.service.common.utils.DbCacheUtil;
import com.alipay.application.service.risk.RiskStatusManager;
import com.alipay.application.service.rule.RuleService;
import com.alipay.application.share.vo.statisics.HomeAggregatedDataVO;
import com.alipay.application.share.vo.statisics.HomePlatformResourceDataVO;
import com.alipay.application.share.vo.statisics.HomeRiskTrendVO;
import com.alipay.common.enums.PlatformType;
import com.alipay.common.enums.ResourceGroupType;
import com.alipay.common.enums.RiskLevel;
import com.alipay.common.enums.StatisticsResource;
import com.alipay.common.utils.DateUtil;
import com.alipay.common.utils.ImageUtil;
import com.alipay.dao.context.UserInfoContext;
import com.alipay.dao.context.UserInfoDTO;
import com.alipay.dao.dto.CloudAccountDTO;
import com.alipay.dao.dto.HomeTopRiskDTO;
import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.dto.RuleScanResultDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/*
 *@title StatisticsServiceImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2024/10/11 11:41
 */

@Service
public class Statistics {

    @Resource
    private CloudAccountMapper cloudAccountMapper;

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    @Resource
    private RuleScanResultMapper ruleScanResultMapper;

    @Resource
    private ResourceMapper resourceMapper;

    @Resource
    private RuleService ruleService;

    @Resource
    private DailyRiskManagementMapper dailyRiskManagementMapper;

    @Resource
    private HistoryDataEverydayStatisticsMapper historyDataEverydayStatisticsMapper;

    @Resource
    private DbCacheUtil dbCacheUtil;

    @Resource
    private CloudRamMapper cloudRamMapper;

    public HomeAggregatedDataVO getAggregatedData() {
        Long tenantId = UserInfoContext.getCurrentUser().getUserTenantId();
        String key = CacheUtil.buildKey("index::get_aggregated_data", tenantId);
        DbCachePO dbCachePO = dbCacheUtil.get(key);
        if (dbCachePO != null) {
            return JSON.parseObject(dbCachePO.getValue(), HomeAggregatedDataVO.class);
        }

        // init data
        HomeAggregatedDataVO todayDataVO = new HomeAggregatedDataVO();
        todayDataVO.setRiskCount(0L);
        todayDataVO.setResourceCount(0L);
        todayDataVO.setPlatformCount(0);
        todayDataVO.setCloudAccountCount(0);

        // yesterday data
        HomeAggregatedDataVO yesterdayAggregatedDataVO = new HomeAggregatedDataVO();
        Date yesterdayEndTime = DateUtil.getYesterdayEndTime();
        String date = DateUtil.dateToString(yesterdayEndTime, "yyyy-MM-dd");
        HistoryDataEverydayStatisticsPO historyDataEverydayStatisticsPO = historyDataEverydayStatisticsMapper.findOne(tenantId, date);

        if (historyDataEverydayStatisticsPO != null) {
            // Get yesterday account account
            yesterdayAggregatedDataVO.setCloudAccountCount(historyDataEverydayStatisticsPO.getCloudAccountCount());

            // get yesterday platform quantity
            yesterdayAggregatedDataVO.setPlatformCount(historyDataEverydayStatisticsPO.getPlatformCount());

            // get yesterday resource quantity
            yesterdayAggregatedDataVO.setResourceCount(historyDataEverydayStatisticsPO.getResourceCount());

            // get yesterday risk quantity
            yesterdayAggregatedDataVO.setRiskCount(historyDataEverydayStatisticsPO.getRiskCount());

            // set yesterday aggregated data
            todayDataVO.setYesterdayHomeAggregatedDataVO(yesterdayAggregatedDataVO);
        }


        // ========================================================
        // get today data
        tenantId = UserInfoContext.getCurrentUser().getGlobalTenantId() != null ? null : tenantId;

        // 1. Get account account
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().build();
        cloudAccountDTO.setTenantId(tenantId);
        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
        if (CollectionUtils.isEmpty(cloudAccountPOS)) {
            return todayDataVO;
        }
        todayDataVO.setCloudAccountCount(cloudAccountPOS.size());

        // 2. Get the number of account platforms
        long platformCount = cloudAccountPOS.stream().map(CloudAccountPO::getPlatform).distinct().count();
        todayDataVO.setPlatformCount((int) platformCount);

        List<String> cloudAccountIdList = cloudAccountPOS.stream().map(CloudAccountPO::getCloudAccountId).toList();
        if (cloudAccountIdList.isEmpty()) {
            return todayDataVO;
        }

        // 3. get resource quantity
        IQueryResourceDTO request = IQueryResourceDTO.builder().tenantId(tenantId).build();
        long cloudResourceInstanceCount = cloudResourceInstanceMapper.findCountByCond(request);
        todayDataVO.setResourceCount(cloudResourceInstanceCount);

        // get risk quantity
        RuleScanResultDTO ruleScanResultDTO = RuleScanResultDTO.builder().tenantId(tenantId)
                .statusList(List.of(RiskStatusManager.RiskStatus.UNREPAIRED.name())).build();
        int ruleScanResultCount = ruleScanResultMapper.findCount(ruleScanResultDTO);
        todayDataVO.setRiskCount((long) ruleScanResultCount);

        dbCacheUtil.put(key, todayDataVO);
        return todayDataVO;
    }

    public List<HomePlatformResourceDataVO> getPlatformResourceData(Long tenantId) {
        String key = CacheUtil.buildKey("index::get_platform_resource_data", tenantId);
        DbCachePO dbCachePO = dbCacheUtil.get(key);
        if (dbCachePO != null) {
            return JSON.parseArray(dbCachePO.getValue(), HomePlatformResourceDataVO.class);
        }

        List<HomePlatformResourceDataVO> result = new ArrayList<>();

        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().build();
        cloudAccountDTO.setTenantId(tenantId);
        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);

        List<String> platformList = cloudAccountPOS.stream().map(CloudAccountPO::getPlatform).distinct().toList();
        for (String platform : platformList) {
            HomePlatformResourceDataVO homePlatformResourceDataVO = new HomePlatformResourceDataVO();
            homePlatformResourceDataVO.setPlatform(platform);
            // The total number of resources to be counted in query
            List<String> resourceTypeList = StatisticsResource.getShowResourceListByPlatform(platform);
            if (resourceTypeList.isEmpty()) {
                continue;
            }

            List<HomePlatformResourceDataVO.ResourceData> resourceDataList = new ArrayList<>();
            for (String resourceType : resourceTypeList) {
                HomePlatformResourceDataVO.ResourceData resourceData = new HomePlatformResourceDataVO.ResourceData();
                resourceData.setResourceType(resourceType);
                // Query resource group name
                ResourcePO resourcePO = resourceMapper.findOne(platform, resourceType);
                if (resourcePO == null) {
                    continue;
                }

                ResourceGroupType resourceGroupType = ResourceGroupType.getByCode(resourcePO.getResourceGroupType());
                resourceData.setResourceGroupTypeName(ResourceGroupType.getDescByCode(resourcePO.getResourceGroupType()));
                resourceData.setResourceGroupType(resourceGroupType.getCode());
                resourceData.setIcon(ImageUtil.ImageToBase64(resourceGroupType.getIcon()));

                // Query the number of assets
                resourceData.setCount(cloudResourceInstanceMapper.findCountByCond(IQueryResourceDTO.builder()
                        .platform(platform).resourceType(resourceType).tenantId(tenantId).build()));
                resourceDataList.add(resourceData);
            }
            homePlatformResourceDataVO.setResouceDataList(resourceDataList);
            homePlatformResourceDataVO.setTotal(resourceDataList.stream()
                    .map(HomePlatformResourceDataVO.ResourceData::getCount).reduce(0L, Long::sum));
            result.add(homePlatformResourceDataVO);
        }

        // Sort by quantity from large to small
        result = result.stream().sorted(Comparator.comparingLong(HomePlatformResourceDataVO::getTotal).reversed())
                .collect(Collectors.toList());

        dbCacheUtil.put(key, result);

        return result;
    }

    public Map<String, Integer> getRiskLevelDataList(Long tenantId) {
        String key = CacheUtil.buildKey("index::get_risk_level_data_list", tenantId);
        DbCachePO dbCachePO = dbCacheUtil.get(key);
        if (dbCachePO != null) {
            return JSON.parseObject(dbCachePO.getValue(), Map.class);
        }

        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().build();
        cloudAccountDTO.setTenantId(tenantId);
        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
        if (cloudAccountPOS.isEmpty()) {
            return Collections.emptyMap();
        }

        List<String> riskStatusList = List.of(RiskStatusManager.RiskStatus.UNREPAIRED.name());
        int highLevelRiskCount = ruleScanResultMapper.findCount(RuleScanResultDTO.builder().tenantId(tenantId)
                .riskLevelList(List.of(RiskLevel.High.name())).statusList(riskStatusList).build());

        int mediumLevelRiskCount = ruleScanResultMapper.findCount(RuleScanResultDTO.builder().tenantId(tenantId)
                .riskLevelList(List.of(RiskLevel.Medium.name())).statusList(riskStatusList).build());

        int lowLevelRiskCount = ruleScanResultMapper.findCount(RuleScanResultDTO.builder().tenantId(tenantId)
                .riskLevelList(List.of(RiskLevel.Low.name())).statusList(riskStatusList).build());

        Map<String, Integer> result = new HashMap<>();
        result.put("highLevelRiskCount", highLevelRiskCount);
        result.put("mediumLevelRiskCount", mediumLevelRiskCount);
        result.put("lowLevelRiskCount", lowLevelRiskCount);

        dbCacheUtil.put(key, result);
        return result;
    }

    public List<Map<String, Object>> getAccessKeyAndAclSituation(Long tenantId) {
        List<Map<String, Object>> result = new ArrayList<>();
        List<PlatformType> platformTypes = List.of(PlatformType.ALI_CLOUD);
        for (PlatformType platformType : platformTypes) {

            int accessKeyCount = cloudRamMapper.getSumAkCountByPlatform(platformType.getPlatform(), tenantId);
            int accessKeyExistAclCount = cloudRamMapper.getSumAkExistAclCountByPlatform(platformType.getPlatform(), tenantId);
            int accessKeyNotExistAclCount = accessKeyCount - accessKeyExistAclCount;
            Map<String, Object> d = new HashMap<>();
            d.put("platform", platformType.getPlatform());
            d.put("platformName", Platform.getPlatformName(platformType.getPlatform()));
            d.put("accessKeyCount", accessKeyCount);
            d.put("accessKeyExistAclCount", accessKeyExistAclCount);
            d.put("accessKeyNotExistAclCount", accessKeyNotExistAclCount);
            result.add(d);
        }

        return result;
    }

    public List<HomeTopRiskDTO> getTopRiskList(Long tenantId) {
        Locale locale = LocaleContextHolder.getLocale();
        String key = CacheUtil.buildKey("index::get_top_risk_list", tenantId, locale.getLanguage());
        DbCachePO dbCachePO = dbCacheUtil.get(key);
        if (dbCachePO != null) {
            return JSON.parseArray(dbCachePO.getValue(), HomeTopRiskDTO.class);
        }
        CloudAccountDTO cloudAccountDTO = CloudAccountDTO.builder().build();
        cloudAccountDTO.setTenantId(tenantId);
        List<CloudAccountPO> cloudAccountPOS = cloudAccountMapper.findList(cloudAccountDTO);
        List<String> cloudAccountIdList = cloudAccountPOS.stream().map(CloudAccountPO::getCloudAccountId).toList();
        if (cloudAccountIdList.isEmpty()) {
            return Collections.emptyList();
        }
        int lackCount = 10;
        List<HomeTopRiskDTO> result = new ArrayList<>(lackCount);

        List<String> riskStatusList = List.of(RiskStatusManager.RiskStatus.UNREPAIRED.name());
        List<HomeTopRiskDTO> highLevelRiskList = ruleScanResultMapper
                .findRiskCountGroupByRuleType(RiskLevel.High.name(), tenantId, riskStatusList, lackCount);
        if (highLevelRiskList.size() >= lackCount) {
            result.addAll(highLevelRiskList.subList(0, lackCount));
            lackCount = 0;
        } else {
            lackCount = lackCount - highLevelRiskList.size();
            result.addAll(highLevelRiskList);
        }

        if (lackCount > 0) {
            List<HomeTopRiskDTO> midLevelRiskList = ruleScanResultMapper
                    .findRiskCountGroupByRuleType(RiskLevel.Medium.name(), tenantId, riskStatusList, lackCount);
            if (midLevelRiskList.size() >= lackCount) {
                result.addAll(midLevelRiskList.subList(0, lackCount));
                lackCount = 0;
            } else {
                lackCount = lackCount - midLevelRiskList.size();
                result.addAll(midLevelRiskList);
            }
        }

        if (lackCount > 0) {
            List<HomeTopRiskDTO> lowLevelRiskList = ruleScanResultMapper
                    .findRiskCountGroupByRuleType(RiskLevel.Low.name(), tenantId, riskStatusList, lackCount);
            if (lowLevelRiskList.size() >= lackCount) {
                result.addAll(lowLevelRiskList.subList(0, lackCount));
            } else {
                result.addAll(lowLevelRiskList);
            }
        }

        for (HomeTopRiskDTO topRiskVO : result) {
            List<String> ruleTypeNameList = ruleService.queryRuleTypeNameList(topRiskVO.getRuleId());
            topRiskVO.setRuleTypeNameList(ruleTypeNameList);
        }

        dbCacheUtil.put(key, result);
        return result;
    }

    public List<HomeRiskTrendVO> getRiskTrend(UserInfoDTO userInfoDTO) {
        Long tenantId = userInfoDTO.getUserTenantId();
        String key = CacheUtil.buildKey("index::get_risk_trend", tenantId);
        DbCachePO dbCachePO = dbCacheUtil.get(key);
        if (dbCachePO != null) {
            return JSON.parseArray(dbCachePO.getValue(), HomeRiskTrendVO.class);
        }

        List<DailyRiskManagementPO> dailyRiskManagementPOList = dailyRiskManagementMapper.findList(tenantId, 7);
        if (dailyRiskManagementPOList == null) {
            return Collections.emptyList();
        }

        List<HomeRiskTrendVO> result = new ArrayList<>();
        for (int i = dailyRiskManagementPOList.size() - 1; i >= 0; i--) {
            DailyRiskManagementPO dailyRiskManagementPO = dailyRiskManagementPOList.get(i);
            HomeRiskTrendVO HomeRiskTrendVO1 = new HomeRiskTrendVO();
            HomeRiskTrendVO1.setDate(dailyRiskManagementPO.getCreateDate());
            HomeRiskTrendVO1.setType("已处理");
            HomeRiskTrendVO1.setCount(dailyRiskManagementPO.getHandleCount());
            result.add(HomeRiskTrendVO1);

            HomeRiskTrendVO homeRiskTrendVO2 = new HomeRiskTrendVO();
            homeRiskTrendVO2.setDate(dailyRiskManagementPO.getCreateDate());
            homeRiskTrendVO2.setType("未处理");
            homeRiskTrendVO2.setCount(dailyRiskManagementPO.getNotHandleCount());
            result.add(homeRiskTrendVO2);
        }

        dbCacheUtil.put(key, result);

        return result;
    }
}
